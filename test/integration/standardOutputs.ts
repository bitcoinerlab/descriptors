// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//npm run test:integration

console.log('Standard output integration tests');
import { networks, Psbt } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
import { RegtestUtils } from 'regtest-client';
const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
//const FINAL_SCRIPTPUBKEY = address.toOutputScript(FINAL_ADDRESS, NETWORK);
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

import * as ecc from '@bitcoinerlab/secp256k1';
import {
  DescriptorsFactory,
  scriptExpressions,
  keyExpressionBIP32,
  signers
} from '../../dist/';
const { wpkhBIP32, shWpkhBIP32, pkhBIP32, trBIP32 } = scriptExpressions;
const { signBIP32, signECPair } = signers;

const { Output, BIP32, ECPair } = DescriptorsFactory(ecc);

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
//The same ecpair will be able to sign all the expressions below:
const expressionsECPair = [
  `pk(${ecpair.publicKey.toString('hex')})`,
  `pkh(${ecpair.publicKey.toString('hex')})`,
  `wpkh(${ecpair.publicKey.toString('hex')})`,
  `sh(wpkh(${ecpair.publicKey.toString('hex')}))`,
  `tr(${ecpair.publicKey.slice(1, 33).toString('hex')})`
];

(async () => {
  const psbtMultiInputs = new Psbt();
  const finalizers = [];
  for (const descriptor of expressionsBIP32) {
    const outputBIP32 = new Output({ descriptor, network: NETWORK });

    let { txId, vout } = await regtestUtils.faucetComplex(
      outputBIP32.getScriptPubKey(),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbt = new Psbt();
    //Add an input and update timelock (if necessary):
    const inputFinalizer = outputBIP32.updatePsbtAsInput({ psbt, vout, txHex });
    const index = psbt.data.inputs.length - 1;
    if (outputBIP32.isSegwit()) {
      //Do some additional tests. Create a tmp psbt using txId and value instead
      //of txHex using Segwit. Passing the value instead of the txHex is not
      //recommended anyway. It's the user's responsibility to make sure that
      //the value is correct to avoid possible fee attacks.
      //updatePsbt should output a Warning message.
      const tmpPsbtSegwit = new Psbt();
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
        value: INITIAL_VALUE
      });
      const indexSegwit = tmpPsbtSegwit.data.inputs.length - 1;
      if (capturedOutput !== 'Warning: missing txHex may allow fee attacks')
        throw new Error(`Error: did not warn about fee attacks`);
      console.warn = originalWarn;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const nonFinalTxHex = (psbt as any).__CACHE.__TX.toHex();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const nonFinalSegwitTxHex = (tmpPsbtSegwit as any).__CACHE.__TX.toHex();
      if (indexSegwit !== index || nonFinalTxHex !== nonFinalSegwitTxHex)
        throw new Error(
          `Error: could not create same psbt ${nonFinalTxHex} for Segwit not using txHex: ${nonFinalSegwitTxHex}`
        );
    }
    //2 ways to achieve the same:
    //psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    new Output({
      descriptor: `addr(${FINAL_ADDRESS})`,
      network: NETWORK
    }).updatePsbtAsOutput({ psbt, value: FINAL_VALUE });
    signBIP32({ psbt, masterNode });
    inputFinalizer({ psbt });
    const spendTx = psbt.extractTransaction();
    await regtestUtils.broadcast(spendTx.toHex());
    await regtestUtils.verify({
      txId: spendTx.getId(),
      address: FINAL_ADDRESS,
      vout: 0,
      value: FINAL_VALUE
    });
    console.log(`${descriptor}: OK`);

    ///Update multiInputs PSBT with a similar BIP32 input
    ({ txId, vout } = await regtestUtils.faucetComplex(
      outputBIP32.getScriptPubKey(),
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
      outputECPair.getScriptPubKey(),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbtECPair = new Psbt();
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
    }).updatePsbtAsOutput({ psbt: psbtECPair, value: FINAL_VALUE });
    signECPair({ psbt: psbtECPair, ecpair });
    inputFinalizer({ psbt: psbtECPair });
    const spendTxECPair = psbtECPair.extractTransaction();
    await regtestUtils.broadcast(spendTxECPair.toHex());
    await regtestUtils.verify({
      txId: spendTxECPair.getId(),
      address: FINAL_ADDRESS,
      vout: 0,
      value: FINAL_VALUE
    });
    console.log(`${descriptor}: OK`);

    ///Update multiInputs PSBT with a similar ECPair input
    ({ txId, vout } = await regtestUtils.faucetComplex(
      outputECPair.getScriptPubKey(),
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
  }).updatePsbtAsOutput({ psbt: psbtMultiInputs, value: FINAL_VALUE });
  //Sign and finish psbtMultiInputs
  signECPair({ psbt: psbtMultiInputs, ecpair });
  signBIP32({ psbt: psbtMultiInputs, masterNode });
  finalizers.forEach(finalizer => finalizer({ psbt: psbtMultiInputs }));

  const spendTxMultiInputs = psbtMultiInputs.extractTransaction();
  await regtestUtils.broadcast(spendTxMultiInputs.toHex());
  await regtestUtils.verify({
    txId: spendTxMultiInputs.getId(),
    address: FINAL_ADDRESS,
    vout: 0,
    value: FINAL_VALUE
  });
  console.log(
    `Spend Psbt with BIP32 & ECPair signers from multiple standard inputs: OK`
  );
})();
