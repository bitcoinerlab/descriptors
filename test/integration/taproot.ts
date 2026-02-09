// Distributed under the MIT software license

console.log('Taproot integration tests');

import { createHash } from 'crypto';
import { networks, Psbt } from 'bitcoinjs-lib';
import { RegtestUtils } from 'regtest-client';
import * as ecc from '@bitcoinerlab/secp256k1';

import { DescriptorsFactory, signers } from '../../dist/index';
import { selectTapLeafCandidates } from '../../dist/tapTree';
import { vsize } from '../helpers/vsize';

import type { ECPairInterface } from 'ecpair';
import type { PartialSig, PsbtInput } from 'bip174/src/lib/interfaces';
import type { OutputInstance } from '../../dist';

const { Output, ECPair, expand } = DescriptorsFactory(ecc);
const { signInputECPair } = signers;
const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const INPUT_VALUE = 50_000;
const FEE = 1_000;
const FINAL_VALUE = INPUT_VALUE - FEE;

const xOnlyHex = (pubkey: Buffer): string =>
  pubkey.slice(1, 33).toString('hex');

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
  expectScriptPath
}: {
  name: string;
  input: OutputInstance;
  signer: ECPairInterface;
  expectScriptPath: boolean;
}): Promise<{ realVsize: number; estimatedVsize: number }> => {
  const { txId, vout } = await regtestUtils.faucetComplex(
    input.getScriptPubKey(),
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

  const destinationAddress = regtestUtils.RANDOM_ADDRESS;
  const destination = new Output({
    descriptor: `addr(${destinationAddress})`,
    network: NETWORK
  });
  destination.updatePsbtAsOutput({ psbt, value: FINAL_VALUE });

  signInputECPair({ psbt, index: 0, ecpair: signer });

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
  const internalSigner = ECPair.fromPrivateKey(Buffer.alloc(32, 1));
  const leafSignerA = ECPair.fromPrivateKey(Buffer.alloc(32, 2));
  const leafSignerB = ECPair.fromPrivateKey(Buffer.alloc(32, 3));

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
    signer: ECPairInterface;
    expectScriptPath: boolean;
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
    }
  ];

  for (const scenario of scenarios) {
    await runScenario(scenario);
  }

  const preimage = Buffer.alloc(32, 9);
  const digest = createHash('sha256').update(preimage).digest('hex');
  const digestExpression = `sha256(${digest})`;
  const expensiveLeafExpression = `and_v(v:pk(${leafBKey}),${digestExpression})`;
  const cheapLeafExpression = leafAExpression;
  const weightedDescriptor = `tr(${internalKey},{${expensiveLeafExpression},${cheapLeafExpression}})`;
  const weightedDescriptorReversed = `tr(${internalKey},{${cheapLeafExpression},${expensiveLeafExpression}})`;
  const weightedPreimages = [
    {
      digest: digestExpression,
      preimage: preimage.toString('hex')
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
