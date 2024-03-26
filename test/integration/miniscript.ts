// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//npm run test:integration

import { networks, Psbt } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
const { encode: afterEncode } = require('bip65');
const { encode: olderEncode } = require('bip68');
import { RegtestUtils } from 'regtest-client';
const regtestUtils = new RegtestUtils();

const BLOCKS = 5;
const NETWORK = networks.regtest;
const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const POLICY = (older: number, after: number) =>
  `or(and(pk(@olderKey),older(${older})),and(pk(@afterKey),after(${after})))`;

console.log(
  `Miniscript integration tests: ${POLICY.toString().match(/`([^`]*)`/)![1]}`
);

import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory, keyExpressionBIP32, signers } from '../../dist/';
import { compilePolicy } from '@bitcoinerlab/miniscript';
const { signBIP32, signECPair } = signers;

const { Output, BIP32, ECPair } = DescriptorsFactory(ecc);

const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);
const ecpair = ECPair.makeRandom();

const keys: {
  [key: string]: {
    originPath: string;
    keyPath: string;
  };
} = {
  '@olderKey': { originPath: "/0'/1'/0'", keyPath: '/0' },
  '@afterKey': { originPath: "/0'/1'/1'", keyPath: '/1' }
};

(async () => {
  //The 3 for loops below test all possible combinations of
  //signer type (BIP32 or ECPair), top-level scripts (sh, wsh, sh-wsh) and
  //who is spending the tx: the "older" or the "after" branch
  for (const keyExpressionType of ['BIP32', 'ECPair']) {
    for (const template of [`sh(SCRIPT)`, `wsh(SCRIPT)`, `sh(wsh(SCRIPT))`]) {
      for (const spendingBranch of Object.keys(keys)) {
        const currentBlockHeight = await regtestUtils.height();
        const after = afterEncode({ blocks: currentBlockHeight + BLOCKS });
        const older = olderEncode({ blocks: BLOCKS }); //relative locktime (sequence)
        //The policy below has been selected for the tests because it has 2 spending
        //branches: the "after" and the "older" branch.
        //Note that the hash to be signed depends on the nSequence and nLockTime
        //values, which is different on each branch.
        //This makes it an interesting test scenario.
        const policy = POLICY(older, after);
        const { miniscript: expandedMiniscript, issane } =
          compilePolicy(policy);
        if (!issane)
          throw new Error(
            `Error: miniscript ${expandedMiniscript} from policy ${policy} is not sane`
          );

        //Note that the hash to be signed is different depending on how we decide
        //to spend the script.
        //Here we decide how are we going to spend the script.
        //spendingBranch is either @olderKey or @afterKey.
        //Use signersPubKeys in Descriptor's constructor to account for this
        let miniscript = expandedMiniscript;
        const signersPubKeys: Buffer[] = [];
        for (const key in keys) {
          const keyValue = keys[key];
          if (!keyValue) throw new Error();
          const { originPath, keyPath } = keyValue;
          const keyExpression = keyExpressionBIP32({
            masterNode,
            originPath,
            keyPath
          });
          const node = masterNode.derivePath(`m${originPath}${keyPath}`);
          const pubkey = node.publicKey;
          if (key === spendingBranch) {
            if (keyExpressionType === 'BIP32') {
              miniscript = miniscript.replace(
                new RegExp(key, 'g'),
                keyExpression
              );
              signersPubKeys.push(pubkey);
            } else {
              miniscript = miniscript.replace(
                new RegExp(key, 'g'),
                ecpair.publicKey.toString('hex')
              );

              signersPubKeys.push(ecpair.publicKey);
            }
          } else {
            //For the non spending branch we can simply use the pubKey as key expressions
            miniscript = miniscript.replace(
              new RegExp(key, 'g'),
              pubkey.toString('hex')
            );
          }
        }
        const descriptor = template.replace('SCRIPT', miniscript);
        const output = new Output({
          descriptor,
          //Use signersPubKeys to mark which spending path will be used
          //(which pubkey must be used)
          signersPubKeys,
          allowMiniscriptInP2SH: true, //Default is false. Activated to test sh(SCRIPT).
          network: NETWORK
        });

        const { txId, vout } = await regtestUtils.faucetComplex(
          output.getScriptPubKey(),
          INITIAL_VALUE
        );
        const { txHex } = await regtestUtils.fetch(txId);
        const psbt = new Psbt();
        const inputFinalizer = output.updatePsbtAsInput({ psbt, vout, txHex });
        //There are different ways to add an output:
        //import { address } from 'bitcoinjs-lib';
        //const FINAL_SCRIPTPUBKEY = address.toOutputScript(FINAL_ADDRESS, NETWORK);
        //psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });
        //But can also be done like this:
        new Output({
          descriptor: `addr(${FINAL_ADDRESS})`,
          network: NETWORK
        }).updatePsbtAsOutput({ psbt, value: FINAL_VALUE });
        if (keyExpressionType === 'BIP32') signBIP32({ masterNode, psbt });
        else signECPair({ ecpair, psbt });
        inputFinalizer({ psbt });
        const spendTx = psbt.extractTransaction();
        //Now let's mine BLOCKS - 1 and see how the node complains about
        //trying to broadcast it now.
        await regtestUtils.mine(BLOCKS - 1);
        try {
          await regtestUtils.broadcast(spendTx.toHex());
          throw new Error(`Error: mining BLOCKS - 1 did not fail`);
        } catch (error) {
          const expectedErrorMessage =
            spendingBranch === '@olderKey' ? 'non-BIP68-final' : 'non-final';
          if (
            error instanceof Error &&
            error.message !== expectedErrorMessage
          ) {
            throw new Error(error.message);
          }
        }
        //Mine the last block needed
        await regtestUtils.mine(1);
        await regtestUtils.broadcast(spendTx.toHex());
        await regtestUtils.verify({
          txId: spendTx.getId(),
          address: FINAL_ADDRESS,
          vout: 0,
          value: FINAL_VALUE
        });
        //Verify the final locking and sequence depending on the branch
        if (spendingBranch === '@afterKey' && spendTx.locktime !== after)
          throw new Error(`Error: final locktime was not correct`);
        if (
          spendingBranch === '@olderKey' &&
          spendTx.ins[0]?.sequence !== older
        )
          throw new Error(`Error: final sequence was not correct`);
        console.log(`\nDescriptor: ${descriptor}`);
        console.log(
          `Branch: ${spendingBranch}, ${keyExpressionType} signing, tx locktime: ${
            psbt.locktime
          }, input sequence: ${psbt.txInputs?.[0]?.sequence?.toString(
            16
          )}, ${output
            .expand()
            .expandedExpression?.replace('@0', '@olderKey')
            .replace('@1', '@afterKey')}: OK`
        );
      }
    }
  }
})();
