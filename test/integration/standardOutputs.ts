// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//npm run test:integration:soft

console.log('Standard output integration tests');
import { networks } from '../../dist';
import { mnemonicToSeedSync } from 'bip39';
import { RegtestUtils } from 'regtest-client';
import { createPsbt, psbtToHex, psbtToTxId } from '../helpers/psbt';
const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const isScure = process.env['BITCOIN_LIB'] === 'scure';
const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
//const FINAL_SCRIPTPUBKEY = address.toOutputScript(FINAL_ADDRESS, NETWORK);
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

import {
  DescriptorsFactory,
  scriptExpressions,
  keyExpressionBIP32,
  signers
} from '../../dist/';
import { createScureLib } from '../../dist/scure';
import * as ecc from '@bitcoinerlab/secp256k1';
import { toHex } from 'uint8array-tools';
import { createKeyFactories } from '../helpers/keyFactories';
const { wpkhBIP32, shWpkhBIP32, pkhBIP32, trBIP32 } = scriptExpressions;
const { signBIP32, signECPair } = signers;

const { Output } = DescriptorsFactory(isScure ? createScureLib(ecc) : ecc);
const { BIP32, ECPair } = createKeyFactories();

const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);
//masterNode will be able to sign all the expressions below:
const expressionsBIP32 = [
  `pk(${keyExpressionBIP32({
    masterNode,
    originPath: "/0'/1'/0'",
    change: 0,
    index: 0
  })})`,
  pkhBIP32({ masterNode, network: NETWORK, account: 0, change: 0, index: 0 }),
  wpkhBIP32({ masterNode, network: NETWORK, account: 0, change: 0, index: 0 }),
  shWpkhBIP32({
    masterNode,
    network: NETWORK,
    account: 0,
    change: 0,
    index: 0
  }),
  trBIP32({ masterNode, network: NETWORK, account: 0, change: 0, index: 0 })
];
if (
  pkhBIP32({ masterNode, network: NETWORK, account: 0, keyPath: '/0/0' }) !==
  pkhBIP32({ masterNode, network: NETWORK, account: 0, change: 0, index: 0 })
)
  throw new Error(`Error: cannot use keyPath <-> change, index, indistinctly`);

const ecpair = ECPair.makeRandom();
const ecpairPubkeyHex = toHex(ecpair.publicKey);
const ecpairXOnlyHex = toHex(ecpair.publicKey.slice(1, 33));
//The same ecpair will be able to sign all the expressions below:
const expressionsECPair = [
  `pk(${ecpairPubkeyHex})`,
  `pkh(${ecpairPubkeyHex})`,
  `wpkh(${ecpairPubkeyHex})`,
  `sh(wpkh(${ecpairPubkeyHex}))`,
  `tr(${ecpairXOnlyHex})`
];

(async () => {
  const psbtMultiInputs = createPsbt(isScure);
  const finalizers = [];
  for (const descriptor of expressionsBIP32) {
    const outputBIP32 = new Output({ descriptor, network: NETWORK });

    let { txId, vout } = await regtestUtils.faucetComplex(
      Buffer.from(outputBIP32.getScriptPubKey()),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbt = createPsbt(isScure);
    //Add an input and update timelock (if necessary):
    const inputFinalizer = outputBIP32.updatePsbtAsInput({ psbt, vout, txHex });
    if (outputBIP32.isSegwit()) {
      //Do some additional tests. Create a tmp psbt using txId and value instead
      //of txHex using Segwit. Passing the value instead of the txHex is not
      //recommended anyway. It's the user's responsibility to make sure that
      //the value is correct to avoid possible fee attacks.
      //updatePsbt should output a Warning message.
      const tmpPsbtSegwit = createPsbt(isScure);
      const originalWarn = console.warn;
      let capturedOutput = '';
      console.warn = (message: string) => {
        capturedOutput += message;
      };
      //Add an input and update timelock (if necessary):
      outputBIP32.updatePsbtAsInput({
        psbt: tmpPsbtSegwit,
        vout,
        txId,
        value: BigInt(INITIAL_VALUE)
      });
      if (capturedOutput !== 'Warning: missing txHex may allow fee attacks')
        throw new Error(`Error: did not warn about fee attacks`);
      console.warn = originalWarn;
    }
    //2 ways to achieve the same:
    //psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    new Output({
      descriptor: `addr(${FINAL_ADDRESS})`,
      network: NETWORK
    }).updatePsbtAsOutput({ psbt, value: BigInt(FINAL_VALUE) });
    signBIP32({ psbt, masterNode });
    inputFinalizer({ psbt });
    await regtestUtils.broadcast(psbtToHex(psbt));
    await regtestUtils.verify({
      txId: psbtToTxId(psbt),
      address: FINAL_ADDRESS,
      vout: 0,
      value: FINAL_VALUE
    });
    console.log(`${descriptor}: OK`);

    ///Update multiInputs PSBT with a similar BIP32 input
    ({ txId, vout } = await regtestUtils.faucetComplex(
      Buffer.from(outputBIP32.getScriptPubKey()),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    //Adds an input and updates timelock (if necessary):
    finalizers.push(
      outputBIP32.updatePsbtAsInput({
        psbt: psbtMultiInputs,
        vout,
        txHex
      })
    );
  }

  for (const descriptor of expressionsECPair) {
    const outputECPair = new Output({
      descriptor,
      network: NETWORK
    });
    let { txId, vout } = await regtestUtils.faucetComplex(
      Buffer.from(outputECPair.getScriptPubKey()),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbtECPair = createPsbt(isScure);
    //Adds an input and updates timelock (if necessary):
    const inputFinalizer = outputECPair.updatePsbtAsInput({
      psbt: psbtECPair,
      vout,
      txHex
    });
    //2 ways to achieve the same:
    //psbtECPair.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    new Output({
      descriptor: `addr(${FINAL_ADDRESS})`,
      network: NETWORK
    }).updatePsbtAsOutput({
      psbt: psbtECPair,
      value: BigInt(FINAL_VALUE)
    });
    signECPair({ psbt: psbtECPair, ecpair });
    inputFinalizer({ psbt: psbtECPair });
    await regtestUtils.broadcast(psbtToHex(psbtECPair));
    await regtestUtils.verify({
      txId: psbtToTxId(psbtECPair),
      address: FINAL_ADDRESS,
      vout: 0,
      value: FINAL_VALUE
    });
    console.log(`${descriptor}: OK`);

    ///Update multiInputs PSBT with a similar ECPair input
    ({ txId, vout } = await regtestUtils.faucetComplex(
      Buffer.from(outputECPair.getScriptPubKey()),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    //Add an input and update timelock (if necessary):
    finalizers.push(
      outputECPair.updatePsbtAsInput({
        psbt: psbtMultiInputs,
        vout,
        txHex
      })
    );
  }

  //2 ways to achieve the same:
  //psbtMultiInputs.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
  new Output({
    descriptor: `addr(${FINAL_ADDRESS})`,
    network: NETWORK
  }).updatePsbtAsOutput({
    psbt: psbtMultiInputs,
    value: BigInt(FINAL_VALUE)
  });
  //Sign and finish psbtMultiInputs
  signECPair({ psbt: psbtMultiInputs, ecpair });
  signBIP32({ psbt: psbtMultiInputs, masterNode });
  finalizers.forEach(finalizer => finalizer({ psbt: psbtMultiInputs }));

  await regtestUtils.broadcast(psbtToHex(psbtMultiInputs));
  await regtestUtils.verify({
    txId: psbtToTxId(psbtMultiInputs),
    address: FINAL_ADDRESS,
    vout: 0,
    value: FINAL_VALUE
  });
  console.log(
    `Spend Psbt with BIP32 & ECPair signers from multiple standard inputs: OK`
  );
})();
