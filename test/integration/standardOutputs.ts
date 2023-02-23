// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//npm run test:integration

console.log('Standard output integration tests');
import { networks, Psbt, address } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
import { RegtestUtils } from 'regtest-client';
const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
const FINAL_SCRIPTPUBKEY = address.toOutputScript(FINAL_ADDRESS, NETWORK);
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

import * as ecc from '@bitcoinerlab/secp256k1';
import {
  DescriptorsFactory,
  DescriptorInterface,
  scriptExpressions,
  keyExpressionBIP32,
  signers
} from '../../src/';
const { wpkhBIP32, shWpkhBIP32, pkhBIP32 } = scriptExpressions;
const { signBIP32, signECPair } = signers;

const { Descriptor, BIP32, ECPair } = DescriptorsFactory(ecc);

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
  shWpkhBIP32({ masterNode, network: NETWORK, account: 0, change: 0, index: 0 })
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
  `sh(wpkh(${ecpair.publicKey.toString('hex')}))`
];

(async () => {
  const psbtMultiInputs = new Psbt();
  const multiInputsDescriptors: DescriptorInterface[] = [];
  for (const expression of expressionsBIP32) {
    const descriptorBIP32 = new Descriptor({ expression, network: NETWORK });

    let { txId, vout } = await regtestUtils.faucetComplex(
      descriptorBIP32.getScriptPubKey(),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbt = new Psbt();
    //Add an input and update timelock (if necessary):
    const index = descriptorBIP32.updatePsbt({ psbt, vout, txHex });
    if (descriptorBIP32.isSegwit()) {
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
      const indexSegwit = descriptorBIP32.updatePsbt({
        psbt: tmpPsbtSegwit,
        vout,
        txId,
        value: INITIAL_VALUE
      });
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
    psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    signBIP32({ psbt, masterNode });
    descriptorBIP32.finalizePsbtInput({ index, psbt });
    const spendTx = psbt.extractTransaction();
    await regtestUtils.broadcast(spendTx.toHex());
    await regtestUtils.verify({
      txId: spendTx.getId(),
      address: FINAL_ADDRESS,
      vout: 0,
      value: FINAL_VALUE
    });
    console.log(`${expression}: OK`);

    ///Update multiInputs PSBT with a similar BIP32 input
    ({ txId, vout } = await regtestUtils.faucetComplex(
      descriptorBIP32.getScriptPubKey(),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    //Adds an input and updates timelock (if necessary):
    const bip32Index = descriptorBIP32.updatePsbt({
      psbt: psbtMultiInputs,
      vout,
      txHex
    });
    multiInputsDescriptors[bip32Index] = descriptorBIP32;
  }

  for (const expression of expressionsECPair) {
    const descriptorECPair = new Descriptor({
      expression,
      network: NETWORK
    });
    let { txId, vout } = await regtestUtils.faucetComplex(
      descriptorECPair.getScriptPubKey(),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbtECPair = new Psbt();
    //Adds an input and updates timelock (if necessary):
    const indexECPair = descriptorECPair.updatePsbt({
      psbt: psbtECPair,
      vout,
      txHex
    });
    psbtECPair.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    signECPair({ psbt: psbtECPair, ecpair });
    descriptorECPair.finalizePsbtInput({
      index: indexECPair,
      psbt: psbtECPair
    });
    const spendTxECPair = psbtECPair.extractTransaction();
    await regtestUtils.broadcast(spendTxECPair.toHex());
    await regtestUtils.verify({
      txId: spendTxECPair.getId(),
      address: FINAL_ADDRESS,
      vout: 0,
      value: FINAL_VALUE
    });
    console.log(`${expression}: OK`);

    ///Update multiInputs PSBT with a similar ECPair input
    ({ txId, vout } = await regtestUtils.faucetComplex(
      descriptorECPair.getScriptPubKey(),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    //Add an input and update timelock (if necessary):
    const ecpairIndex = descriptorECPair.updatePsbt({
      psbt: psbtMultiInputs,
      vout,
      txHex
    });
    multiInputsDescriptors[ecpairIndex] = descriptorECPair;
  }

  psbtMultiInputs.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
  //Sign and finish psbtMultiInputs
  signECPair({ psbt: psbtMultiInputs, ecpair });
  signBIP32({ psbt: psbtMultiInputs, masterNode });
  multiInputsDescriptors.forEach((descriptor, index) =>
    descriptor.finalizePsbtInput({ index, psbt: psbtMultiInputs })
  );

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
