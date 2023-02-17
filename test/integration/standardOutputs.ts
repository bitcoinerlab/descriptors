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
import { DescriptorsFactory, DescriptorInterface } from '../../src/';
import type { ECPairInterface } from 'ecpair';

const { Descriptor, BIP32, ECPair } = DescriptorsFactory(ecc);

const templates = [
  { template: 'pk(@key)', originPath: "/0'/1'/0'", keyPath: '/0/0' },
  { template: 'pkh(@key)', originPath: "/44'/1'/0'", keyPath: '/0/0' },
  { template: 'wpkh(@key)', originPath: "/84'/1'/0'", keyPath: '/0/0' },
  { template: 'sh(wpkh(@key))', originPath: "/49'/1'/0'", keyPath: '/0/0' }
];

const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);
const masterFingerprint = masterNode.fingerprint;

(async () => {
  const psbtLarge = new Psbt();
  const descriptorsLarge: DescriptorInterface[] = [];
  const ecpairs: ECPairInterface[] = [];
  for (const { originPath, keyPath, template } of templates) {
    //console.log({ originPath, keyPath, template });
    const origin = `[${masterFingerprint.toString('hex')}${originPath}]`;
    const xpub = masterNode
      .derivePath(`m${originPath}`)
      .neutered()
      .toBase58()
      .toString();
    const keyRoot = `${origin}${xpub}`;
    const keyExpression = `${keyRoot}${keyPath}`;
    const expression = template.replace('@key', keyExpression);
    const descriptorBIP32 = new Descriptor({ expression, network: NETWORK });
    //console.log({ expression }, 'Expansion:', descriptorBIP32.expand());

    let { txId, vout } = await regtestUtils.faucetComplex(
      descriptorBIP32.getScriptPubKey(),
      INITIAL_VALUE
    );
    let { txHex } = await regtestUtils.fetch(txId);
    const psbt = new Psbt();
    const index = descriptorBIP32.updatePsbt({ psbt, vout, txHex });
    if (descriptorBIP32.isSegwit()) {
      //Do some additional tests. Create a tmp psbt using txId and value instead
      //of txHex using Segwit
      const psbtSegwit = new Psbt();
      const indexSegwit = descriptorBIP32.updatePsbt({
        psbt: psbtSegwit,
        vout,
        txId,
        value: INITIAL_VALUE
      });
      const nonFinalTxHex = (psbt as any).__CACHE.__TX.toHex();
      const nonFinalSegwitTxHex = (psbtSegwit as any).__CACHE.__TX.toHex();
      if (indexSegwit !== index || nonFinalTxHex !== nonFinalSegwitTxHex)
        throw new Error(
          `Error: could not create same psbt ${nonFinalTxHex} for Segwit not using txHex: ${nonFinalSegwitTxHex}`
        );
    }
    psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    psbt.signInputHD(index, masterNode);
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

    //
    //
    ///Update large PSBT with the BIP32 input
    //
    //
    ({ txId, vout } = await regtestUtils.faucetComplex(
      descriptorBIP32.getScriptPubKey(),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    descriptorBIP32.updatePsbt({ psbt: psbtLarge, vout, txHex });
    descriptorsLarge.push(descriptorBIP32);

    //
    //
    //Using ECPAIR
    //
    //
    const node = masterNode.derivePath(`m${originPath}${keyPath}`);
    const ecpair: ECPairInterface = ECPair.fromPrivateKey(node.privateKey!);
    const expressionECPair = template.replace(
      '@key',
      ecpair.publicKey.toString('hex')
    );
    const descriptorECPair = new Descriptor({
      expression: expressionECPair,
      network: NETWORK
    });
    //console.log({ expressionECPair }, 'Expansion:', descriptorECPair.expand());
    ({ txId, vout } = await regtestUtils.faucetComplex(
      descriptorECPair.getScriptPubKey(),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    const psbtECPair = new Psbt();
    const indexECPair = descriptorECPair.updatePsbt({
      psbt: psbtECPair,
      vout,
      txHex
    });
    psbtECPair.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
    psbtECPair.signInput(indexECPair, ecpair);
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
    console.log(`${expressionECPair}: OK`);

    //
    //
    ///Update large PSBT with the ECPair input
    //
    //
    ({ txId, vout } = await regtestUtils.faucetComplex(
      descriptorECPair.getScriptPubKey(),
      INITIAL_VALUE
    ));
    ({ txHex } = await regtestUtils.fetch(txId));
    const ecpairIndex = descriptorECPair.updatePsbt({
      psbt: psbtLarge,
      vout,
      txHex
    });
    descriptorsLarge.push(descriptorECPair);
    ecpairs[ecpairIndex] = ecpair;
  }

  //
  //
  //Sign and finish psbtLarge
  //
  //
  psbtLarge.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
  descriptorsLarge.map((descriptor, index) => {
    if (ecpairs[index]) {
      psbtLarge.signInput(index, ecpairs[index]!);
    } else {
      psbtLarge.signInputHD(index, masterNode);
    }
    descriptor.finalizePsbtInput({ index, psbt: psbtLarge });
  });
  const spendTxLarge = psbtLarge.extractTransaction();
  await regtestUtils.broadcast(spendTxLarge.toHex());
  await regtestUtils.verify({
    txId: spendTxLarge.getId(),
    address: FINAL_ADDRESS,
    vout: 0,
    value: FINAL_VALUE
  });
  console.log(`Spend Psbt using all previous inputs: OK`);
})();
