// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//npm run test:integration

console.log('Miniscript integration tests');
import { networks, Psbt, address } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
const { encode: afterEncode } = require('bip65');
const { encode: olderEncode } = require('bip68');
import type { ECPairInterface } from 'ecpair';
import { RegtestUtils } from 'regtest-client';
const regtestUtils = new RegtestUtils();

const BLOCKS = 5;
const NETWORK = networks.regtest;
const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
const FINAL_SCRIPTPUBKEY = address.toOutputScript(FINAL_ADDRESS, NETWORK);
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory } from '../../src/';

import { compilePolicy } from '@bitcoinerlab/miniscript';

const { Descriptor, BIP32, ECPair } = DescriptorsFactory(ecc);

const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);
const masterFingerprint = masterNode.fingerprint;

const keys: {
  [key: string]: {
    originPath: string;
    keyPath: string;
    pubkey?: Buffer;
    ecpair?: ECPairInterface;
  };
} = {
  '@olderKey': { originPath: "/0'/0'/0'", keyPath: '/0' },
  '@afterKey': { originPath: "/0'/1'/1'", keyPath: '/1' }
};

const templates = [`sh(SCRIPT)`, `wsh(SCRIPT)`, `sh(wsh(SCRIPT))`];

(async () => {
  const currentBlockHeight = await regtestUtils.height();
  const AFTER = afterEncode({ blocks: currentBlockHeight + BLOCKS });
  const OLDER = olderEncode({ blocks: BLOCKS }); //relative locktime (sequence)
  const POLICY = `or(and(pk(@olderKey),older(${OLDER})),and(pk(@afterKey),after(${AFTER})))`;
  const { miniscript: expandedMiniscript, issane } = compilePolicy(POLICY);
  if (!issane)
    throw new Error(
      `Error: miniscript ${expandedMiniscript} from policy ${POLICY} is not sane`
    );

  for (const keyExpressionType of ['BIP32', 'ECPair']) {
    for (const template of templates) {
      for (const spendingBranch of Object.keys(keys)) {
        //Note that the hash to be signed is different depending on how we decide
        //to spend the script.
        //Here we decide how are we going to spend the script.
        //spendingBranch is either @olderKey or @afterKey.
        //Use signersPubKeys in Descriptor's constructor to account for this
        let miniscript = expandedMiniscript;
        for (const key in keys) {
          const keyValue = keys[key];
          if (!keyValue) throw new Error();
          const { originPath, keyPath } = keyValue;
          const xpub = masterNode
            .derivePath(`m${originPath}`)
            .neutered()
            .toBase58()
            .toString();
          const origin = `[${masterFingerprint.toString('hex')}${originPath}]`;
          const keyRoot = `${origin}${xpub}`;
          const keyExpression = `${keyRoot}${keyPath}`;
          const node = masterNode.derivePath(`m${originPath}${keyPath}`);
          keyValue.pubkey = node.publicKey;
          if (keyExpressionType === 'BIP32') {
            //Here we will only provide bip32 keyExpressions to the keys that
            //must be signed. Providing bip32 to all keyExpressions would also work
            //but we use a pubkey as keyExpression to make sure that a valid
            //tx is created just using the strictly necessary signatures.
            if (key === spendingBranch)
              miniscript = miniscript.replaceAll(key, keyExpression);
            else
              miniscript = miniscript.replaceAll(
                key,
                keyValue.pubkey.toString('hex')
              );
          } else {
            miniscript = miniscript.replaceAll(
              key,
              keyValue.pubkey.toString('hex')
            );
            if (key === spendingBranch)
              keyValue.ecpair = ECPair.fromPrivateKey(node.privateKey!);
          }
        }
        const expression = template.replace('SCRIPT', miniscript);
        const descriptor = new Descriptor({
          expression,
          signersPubKeys: [keys[spendingBranch]?.pubkey!],
          allowMiniscriptInP2SH: true,
          network: NETWORK
        });

        let { txId, vout } = await regtestUtils.faucetComplex(
          descriptor.getScriptPubKey(),
          INITIAL_VALUE
        );
        let { txHex } = await regtestUtils.fetch(txId);
        const psbt = new Psbt();
        const index = descriptor.updatePsbt({ txHex, vout, psbt });
        psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
        if (keyExpressionType === 'BIP32') psbt.signInputHD(index, masterNode);
        else psbt.signInput(index, keys[spendingBranch]?.ecpair!);
        descriptor.finalizePsbtInput({ index, psbt });
        const spendTx = psbt.extractTransaction();
        await regtestUtils.mine(BLOCKS);
        await regtestUtils.broadcast(spendTx.toHex());
        await regtestUtils.verify({
          txId: spendTx.getId(),
          address: FINAL_ADDRESS,
          vout: 0,
          value: FINAL_VALUE
        });
        console.log(
          `Branch: ${spendingBranch}, ${keyExpressionType} signing, tx locktime: ${psbt.locktime}, input sequence: ${psbt.txInputs?.[0]?.sequence?.toString(16)}, ${expression}: OK`
        );
      }
    }
  }
})();
