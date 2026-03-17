// Distributed under the MIT software license

console.log('Taproot integration tests');

import { createHash } from 'crypto';
import { networks, Psbt } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { encode: afterEncode } = require('bip65');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { encode: olderEncode } = require('bip68');
import { RegtestUtils } from 'regtest-client';
import * as ecc from '@bitcoinerlab/secp256k1';
import { toHex } from 'uint8array-tools';

import {
  DescriptorsFactory,
  keyExpressionBIP32,
  signers
} from '../../dist/index';
import { selectTapLeafCandidates } from '../../dist/tapTree';
import { vsize } from '../helpers/vsize';

import type { ECPairInterface } from 'ecpair';
import type { BIP32Interface } from 'bip32';
import type { PartialSig, PsbtInput } from 'bip174';
import type { OutputInstance } from '../../dist';

const { Output, ECPair, BIP32, expand } = DescriptorsFactory(ecc);
const { signInputECPair, signBIP32 } = signers;
const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const INPUT_VALUE = 50_000;
const FEE = 1_000;
const FINAL_VALUE = INPUT_VALUE - FEE;
const TIMELOCK_BLOCKS = 5;
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const xOnlyHex = (pubkey: Uint8Array): string => toHex(pubkey.slice(1, 33));

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message);
};

const signaturesFromInput = (input: PsbtInput): Array<PartialSig> => {
  if (input.tapScriptSig && input.tapScriptSig.length > 0) {
    return input.tapScriptSig.map(sig => ({
      pubkey: sig.pubkey,
      signature: sig.signature
    }));
  }

  if (input.tapKeySig && input.tapInternalKey) {
    return [{ pubkey: input.tapInternalKey, signature: input.tapKeySig }];
  }

  if (input.partialSig && input.partialSig.length > 0) return input.partialSig;

  throw new Error('Error: could not extract signatures from PSBT input');
};

const runScenario = async ({
  name,
  input,
  signer,
  masterNode,
  expectScriptPath,
  expectTapBip32Derivation = false,
  timelock
}: {
  name: string;
  input: OutputInstance;
  signer?: ECPairInterface;
  masterNode?: BIP32Interface;
  expectScriptPath: boolean;
  expectTapBip32Derivation?: boolean;
  timelock?: {
    blocks: number;
    expectedPrematureBroadcastError: 'non-final' | 'non-BIP68-final';
    expectedLocktime?: number;
    expectedSequence?: number;
  };
}): Promise<{ realVsize: number; estimatedVsize: number }> => {
  const { txId, vout } = await regtestUtils.faucetComplex(
    Buffer.from(input.getScriptPubKey()),
    INPUT_VALUE
  );
  const { txHex } = await regtestUtils.fetch(txId);

  const psbt = new Psbt({ network: NETWORK });
  const finalize = input.updatePsbtAsInput({ psbt, vout, txHex });

  const beforeSignInput = psbt.data.inputs[0];
  if (!beforeSignInput) throw new Error('Error: missing PSBT input');

  if (expectScriptPath) {
    assert(
      Boolean(beforeSignInput.tapLeafScript?.length),
      `Error: ${name} expected tapLeafScript to be populated`
    );
  } else {
    assert(
      !beforeSignInput.tapLeafScript ||
        beforeSignInput.tapLeafScript.length === 0,
      `Error: ${name} expected no tapLeafScript`
    );
  }

  if (expectTapBip32Derivation) {
    assert(
      Boolean(beforeSignInput.tapBip32Derivation?.length),
      `Error: ${name} expected tapBip32Derivation to be populated`
    );
  }

  const destinationAddress = regtestUtils.RANDOM_ADDRESS;
  const destination = new Output({
    descriptor: `addr(${destinationAddress})`,
    network: NETWORK
  });
  destination.updatePsbtAsOutput({ psbt, value: BigInt(FINAL_VALUE) });

  if (masterNode) {
    signBIP32({ psbt, masterNode });
  } else {
    if (!signer)
      throw new Error(`Error: ${name} requires signer or masterNode`);
    signInputECPair({ psbt, index: 0, ecpair: signer });
  }

  const afterSignInput = psbt.data.inputs[0];
  if (!afterSignInput)
    throw new Error('Error: missing PSBT input after signing');
  const signatures = signaturesFromInput(afterSignInput);

  finalize({ psbt });
  const tx = psbt.extractTransaction();
  const realVsize = tx.virtualSize();

  const estimatedVsize = vsize([input], [destination], [signatures]);

  if (estimatedVsize !== realVsize) {
    throw new Error(
      `Error: ${name} vsize mismatch. estimated=${estimatedVsize}, real=${realVsize}`
    );
  }

  if (timelock?.expectedLocktime !== undefined) {
    if (tx.locktime !== timelock.expectedLocktime)
      throw new Error(
        `Error: ${name} locktime mismatch. expected=${timelock.expectedLocktime}, got=${tx.locktime}`
      );
  }
  if (timelock?.expectedSequence !== undefined) {
    const sequence = tx.ins[0]?.sequence;
    if (sequence === undefined)
      throw new Error(`Error: ${name} missing input sequence`);
    if (sequence !== timelock.expectedSequence)
      throw new Error(
        `Error: ${name} sequence mismatch. expected=${timelock.expectedSequence}, got=${sequence}`
      );
  }

  if (timelock) {
    let blocksToMineBeforePrematureBroadcast = timelock.blocks - 1;

    // For absolute timelocks (`after(...)`), align with the current chain height
    // so we can always test: mine until one block before maturity -> fail,
    // mine one more block -> success.
    if (timelock.expectedLocktime !== undefined) {
      const currentHeight = await regtestUtils.height();
      const blocksUntilMaturity = timelock.expectedLocktime - currentHeight;
      if (blocksUntilMaturity <= 0)
        throw new Error(
          `Error: ${name} absolute timelock is already mature (height=${currentHeight}, locktime=${timelock.expectedLocktime})`
        );
      blocksToMineBeforePrematureBroadcast = blocksUntilMaturity - 1;
    }

    if (blocksToMineBeforePrematureBroadcast > 0)
      await regtestUtils.mine(blocksToMineBeforePrematureBroadcast);
    try {
      await regtestUtils.broadcast(tx.toHex());
      throw new Error(`Error: ${name} should fail before timelock matures`);
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      if (error.message !== timelock.expectedPrematureBroadcastError)
        throw new Error(error.message);
    }
    await regtestUtils.mine(1);
  }

  await regtestUtils.broadcast(tx.toHex());
  await regtestUtils.verify({
    txId: tx.getId(),
    address: destinationAddress,
    vout: 0,
    value: FINAL_VALUE
  });

  console.log(`${name}: OK (vsize=${realVsize})`);
  return { realVsize, estimatedVsize };
};

(async () => {
  const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);

  const internalSigner = ECPair.fromPrivateKey(new Uint8Array(32).fill(1));
  const leafSignerA = ECPair.fromPrivateKey(new Uint8Array(32).fill(2));
  const leafSignerB = ECPair.fromPrivateKey(new Uint8Array(32).fill(3));

  const internalKey = xOnlyHex(internalSigner.publicKey);
  const leafAKey = xOnlyHex(leafSignerA.publicKey);
  const leafBKey = xOnlyHex(leafSignerB.publicKey);
  const leafAExpression = `pk(${leafAKey})`;
  const leafBExpression = `pk(${leafBKey})`;

  const trKeyDescriptor = `tr(${internalKey})`;
  const trTreeDescriptor = `tr(${internalKey},{${leafAExpression},${leafBExpression}})`;

  const { tapTreeInfo } = expand({
    descriptor: trTreeDescriptor,
    network: NETWORK
  });
  if (!tapTreeInfo) throw new Error('Error: tapTreeInfo not available');
  const selected = selectTapLeafCandidates({
    tapTreeInfo,
    tapLeaf: leafAExpression
  })[0];
  if (!selected)
    throw new Error('Error: could not derive tapLeafHash for selected leaf');

  const scenarios: Array<{
    name: string;
    input: OutputInstance;
    signer?: ECPairInterface;
    masterNode?: BIP32Interface;
    expectScriptPath: boolean;
    expectTapBip32Derivation?: boolean;
  }> = [
    {
      name: 'tr(KEY) key-path spend',
      input: new Output({ descriptor: trKeyDescriptor, network: NETWORK }),
      signer: internalSigner,
      expectScriptPath: false
    },
    {
      name: 'tr(KEY,TREE) script-path spend using tapLeaf string',
      input: new Output({
        descriptor: trTreeDescriptor,
        network: NETWORK,
        taprootSpendPath: 'script',
        tapLeaf: leafAExpression
      }),
      signer: leafSignerA,
      expectScriptPath: true
    },
    {
      name: 'tr(KEY,TREE) script-path spend using tapLeaf hash',
      input: new Output({
        descriptor: trTreeDescriptor,
        network: NETWORK,
        taprootSpendPath: 'script',
        tapLeaf: selected.tapLeafHash
      }),
      signer: leafSignerA,
      expectScriptPath: true
    },
    {
      name: 'tr(BIP32 KEY) key-path spend',
      input: new Output({
        descriptor: `tr(${keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/0'",
          keyPath: '/0'
        })})`,
        network: NETWORK
      }),
      masterNode,
      expectScriptPath: false,
      expectTapBip32Derivation: true
    },
    {
      name: 'tr(BIP32 KEY,TREE) script-path spend using tapLeaf string',
      input: (() => {
        const internal = keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/1'",
          keyPath: '/0'
        });
        const leafA = keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/2'",
          keyPath: '/0'
        });
        const leafB = keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/3'",
          keyPath: '/0'
        });
        const descriptor = `tr(${internal},{pk(${leafA}),pk(${leafB})})`;
        return new Output({
          descriptor,
          network: NETWORK,
          taprootSpendPath: 'script',
          tapLeaf: `pk(${leafA})`
        });
      })(),
      masterNode,
      expectScriptPath: true,
      expectTapBip32Derivation: true
    },
    {
      name: 'tr(BIP32 KEY,TREE) script-path spend using tapLeaf hash',
      input: (() => {
        const internal = keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/4'",
          keyPath: '/0'
        });
        const leafA = keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/5'",
          keyPath: '/0'
        });
        const leafB = keyExpressionBIP32({
          masterNode,
          originPath: "/0'/9'/6'",
          keyPath: '/0'
        });
        const descriptor = `tr(${internal},{pk(${leafA}),pk(${leafB})})`;
        const { tapTreeInfo } = expand({ descriptor, network: NETWORK });
        if (!tapTreeInfo)
          throw new Error('Error: tapTreeInfo not available for BIP32 tree');
        const selectedLeaf = selectTapLeafCandidates({
          tapTreeInfo,
          tapLeaf: `pk(${leafA})`
        })[0];
        if (!selectedLeaf)
          throw new Error('Error: could not derive tapLeafHash for BIP32 leaf');
        return new Output({
          descriptor,
          network: NETWORK,
          taprootSpendPath: 'script',
          tapLeaf: selectedLeaf.tapLeafHash
        });
      })(),
      masterNode,
      expectScriptPath: true,
      expectTapBip32Derivation: true
    },
    {
      name: 'tr(KEY,TREE) script-path spend using sortedmulti_a leaf',
      input: (() => {
        const sortedMultiALeaf = `sortedmulti_a(1,${leafBKey},${leafAKey})`;
        return new Output({
          descriptor: `tr(${internalKey},${sortedMultiALeaf})`,
          network: NETWORK,
          taprootSpendPath: 'script',
          tapLeaf: sortedMultiALeaf
        });
      })(),
      signer: leafSignerA,
      expectScriptPath: true
    }
  ];

  for (const scenario of scenarios) {
    await runScenario(scenario);
  }

  const olderTimelock = olderEncode({ blocks: TIMELOCK_BLOCKS });

  const relativeTimelockLeafExpression = `and_v(v:pk(${leafBKey}),older(${olderTimelock}))`;
  await runScenario({
    name: 'tr(KEY,TREE) script-path relative timelock (older) enforced',
    input: new Output({
      descriptor: `tr(${internalKey},{${leafAExpression},${relativeTimelockLeafExpression}})`,
      network: NETWORK,
      taprootSpendPath: 'script',
      tapLeaf: relativeTimelockLeafExpression
    }),
    signer: leafSignerB,
    expectScriptPath: true,
    timelock: {
      blocks: TIMELOCK_BLOCKS,
      expectedPrematureBroadcastError: 'non-BIP68-final',
      expectedSequence: olderTimelock
    }
  });

  const afterTimelock = afterEncode({
    blocks: (await regtestUtils.height()) + TIMELOCK_BLOCKS
  });
  const absoluteTimelockLeafExpression = `and_v(v:pk(${leafBKey}),after(${afterTimelock}))`;
  await runScenario({
    name: 'tr(KEY,TREE) script-path absolute timelock (after) enforced',
    input: new Output({
      descriptor: `tr(${internalKey},{${leafAExpression},${absoluteTimelockLeafExpression}})`,
      network: NETWORK,
      taprootSpendPath: 'script',
      tapLeaf: absoluteTimelockLeafExpression
    }),
    signer: leafSignerB,
    expectScriptPath: true,
    timelock: {
      blocks: TIMELOCK_BLOCKS,
      expectedPrematureBroadcastError: 'non-final',
      expectedLocktime: afterTimelock
    }
  });

  const preimage = new Uint8Array(32).fill(9);
  const digest = createHash('sha256').update(preimage).digest('hex');
  const digestExpression = `sha256(${digest})`;
  const expensiveLeafExpression = `and_v(v:pk(${leafBKey}),${digestExpression})`;
  const cheapLeafExpression = leafAExpression;
  const weightedDescriptor = `tr(${internalKey},{${expensiveLeafExpression},${cheapLeafExpression}})`;
  const weightedDescriptorReversed = `tr(${internalKey},{${cheapLeafExpression},${expensiveLeafExpression}})`;
  const weightedPreimages = [
    {
      digest: digestExpression,
      preimage: toHex(preimage)
    }
  ];

  const weightedOutput = new Output({
    descriptor: weightedDescriptor,
    network: NETWORK,
    taprootSpendPath: 'script',
    preimages: weightedPreimages
  });
  const weightedOutputReversed = new Output({
    descriptor: weightedDescriptorReversed,
    network: NETWORK,
    taprootSpendPath: 'script',
    preimages: weightedPreimages
  });

  assert(
    weightedOutput.getAddress() === weightedOutputReversed.getAddress(),
    `Error: swapping leaf order should keep same taproot address`
  );

  const autoResult = await runScenario({
    name: 'tr(KEY,TREE) script-path auto-selects cheapest leaf',
    input: weightedOutput,
    signer: leafSignerA,
    expectScriptPath: true
  });

  const autoResultReversed = await runScenario({
    name: 'tr(KEY,TREE) script-path auto-select with reversed leaf order',
    input: weightedOutputReversed,
    signer: leafSignerA,
    expectScriptPath: true
  });

  const forcedExpensiveResult = await runScenario({
    name: 'tr(KEY,TREE) script-path forced expensive leaf',
    input: new Output({
      descriptor: weightedDescriptor,
      network: NETWORK,
      taprootSpendPath: 'script',
      tapLeaf: expensiveLeafExpression,
      preimages: weightedPreimages
    }),
    signer: leafSignerB,
    expectScriptPath: true
  });

  assert(
    autoResult.realVsize === autoResultReversed.realVsize,
    `Error: auto-select vsize changed after swapping leaf order`
  );
  assert(
    autoResult.estimatedVsize === autoResultReversed.estimatedVsize,
    `Error: auto-select estimate changed after swapping leaf order`
  );

  assert(
    autoResult.realVsize < forcedExpensiveResult.realVsize,
    `Error: auto-selected script-path should be cheaper than forced expensive leaf`
  );
})();
