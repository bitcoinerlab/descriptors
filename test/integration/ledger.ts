// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//npm run test:integration

console.log(
  'Ledger integration tests: 2 pkh inputs (one internal & external addresses) + 1 miniscript input (cosigned with a software wallet) -> 1 output'
);
const Transport = require('@ledgerhq/hw-transport-node-hid').default;
import { AppClient } from 'ledger';
import { networks, Psbt, address } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
const { encode: olderEncode } = require('bip68');
import { RegtestUtils } from 'regtest-client';
const regtestUtils = new RegtestUtils();

//TODO: this is temporal. Move to src/ledger.ts and then import from ../src
import { signLedger, signBIP32 } from '../../src/signers';
import { LedgerState, registerLedgerPolicy } from '../../src/ledger';
import {
  keyExpressionBIP32,
  keyExpressionLedger,
  pkhLedger
} from '../../src/keyExpressions';

const BLOCKS = 5;
const NETWORK = networks.regtest;
const INITIAL_VALUE = 2e4;
const FINAL_VALUE = INITIAL_VALUE - 1000;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
const FINAL_SCRIPTPUBKEY = address.toOutputScript(FINAL_ADDRESS, NETWORK);
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const OLDER = olderEncode({ blocks: BLOCKS });
const PREIMAGE =
  '107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f';
const SHA256_DIGEST =
  '6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333';

let POLICY = `and(and(and(pk(@ledger),pk(@soft)),older(${OLDER})),sha256(${SHA256_DIGEST}))`;
//Ledger Btc App will require an extra click on "non-standard" paths.
const ORIGIN_PATH = `/0'/1'/0'`;
const RECEIVE_INDEX = 0;

import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory, DescriptorInterface } from '../../src/';
const { Descriptor, BIP32 } = DescriptorsFactory(ecc);

import { compilePolicy } from '@bitcoinerlab/miniscript';

const psbt = new Psbt({ network: NETWORK });
//Build the miniscript-based descriptor:
const { miniscript, issane } = compilePolicy(POLICY);
if (!issane) throw new Error(`Error: miniscript not sane`);

let txHex: string;
let txId: string;
let vout: number;
let inputIndex: number;
const psbtInputDescriptors: DescriptorInterface[] = [];

(async () => {
  const transport = await Transport.create();
  const ledgerClient = new AppClient(transport);
  const ledgerState: LedgerState = {};

  const pkhExternalExpression = await pkhLedger({
    ledgerClient,
    ledgerState,
    account: 0,
    network: NETWORK,
    change: 0,
    index: 0
  });
  const pkhExternalDescriptor = new Descriptor({
    network: NETWORK,
    expression: pkhExternalExpression
  });
  ({ txId, vout } = await regtestUtils.faucet(
    pkhExternalDescriptor.getAddress(),
    INITIAL_VALUE
  ));
  txHex = (await regtestUtils.fetch(txId)).txHex;
  inputIndex = pkhExternalDescriptor.updatePsbt({
    txHex,
    vout,
    psbt
  });
  //It is important that they are indexed wrt its psbt input number
  psbtInputDescriptors[inputIndex] = pkhExternalDescriptor;

  const pkhChangeExpression = await pkhLedger({
    ledgerClient,
    ledgerState,
    account: 0,
    network: NETWORK,
    change: 1,
    index: 0
  });
  const pkhChangeDescriptor = new Descriptor({
    network: NETWORK,
    expression: pkhChangeExpression
  });
  ({ txId, vout } = await regtestUtils.faucet(
    pkhChangeDescriptor.getAddress(),
    INITIAL_VALUE
  ));
  txHex = (await regtestUtils.fetch(txId)).txHex;
  inputIndex = pkhChangeDescriptor.updatePsbt({ txHex, vout, psbt });
  //It is important that they are indexed wrt its psbt input number
  psbtInputDescriptors[inputIndex] = pkhChangeDescriptor;

  const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);

  const softKeyExpression = keyExpressionBIP32({
    masterNode,
    originPath: ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  const ledgerKeyExpression = await keyExpressionLedger({
    ledgerClient,
    ledgerState,
    originPath: ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  //The ranged descriptor expression for external (receive) addresses (change = 0):
  const externalExpression = `wsh(${miniscript
    .replace('@ledger', ledgerKeyExpression)
    .replace('@soft', softKeyExpression)})`;
  //Get the descriptor for index RECEIVE_INDEX
  const miniscriptDescriptor = new Descriptor({
    expression: externalExpression,
    index: RECEIVE_INDEX,
    preimages: [{ digest: `sha256(${SHA256_DIGEST})`, preimage: PREIMAGE }],
    network: NETWORK
  });
  const receiveAddress = miniscriptDescriptor.getAddress();
  //Send some BTC to the script
  ({ txId, vout } = await regtestUtils.faucet(receiveAddress, INITIAL_VALUE));
  txHex = (await regtestUtils.fetch(txId)).txHex;
  //Now, let's build the psbt that will spend the script:

  //Adds an input (including bip32 & sequence) & sets the tx timelock, if needed
  inputIndex = miniscriptDescriptor.updatePsbt({
    txHex,
    vout,
    psbt
  });
  //It is important that they are indexed wrt its psbt input number
  psbtInputDescriptors[inputIndex] = miniscriptDescriptor;

  //This is where we'll send the funds. Just a random address.
  psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });

  //=============
  //Register ledger policies of non-standard descriptors.
  //Registration is stored in ledgerState and is a necessary step before
  //signing for non-standard policies.
  await registerLedgerPolicy({
    descriptor: miniscriptDescriptor,
    policyName: 'BitcoinerLab',
    ledgerClient,
    ledgerState,
  });

  //=============
  //Sign the psbt with the Ledger:
  await signLedger({
    psbt,
    descriptors: psbtInputDescriptors,
    ledgerClient,
    ledgerState
  });
  //Now sign the PSBT with the BIP32 node (the software wallet)
  signBIP32({ psbt, node: masterNode });

  //=============
  //Finalize the psbt:
  //descriptors are indexed wrt its psbt input number:
  psbtInputDescriptors.forEach((descriptor, inputIndex) =>
    descriptor.finalizePsbtInput({ index: inputIndex, psbt })
  );

  const spendTx = psbt.extractTransaction();
  //We need to mine BLOCKS in order to be accepted
  await regtestUtils.mine(BLOCKS);
  const resultSpend = await regtestUtils.broadcast(spendTx.toHex());

  //Verify that the tx was mined. This will throw if not ok
  await regtestUtils.verify({
    txId: spendTx.getId(),
    address: FINAL_ADDRESS,
    vout: 0,
    value: FINAL_VALUE
  });

  console.log({
    miniscript,
    spendTx: spendTx.toHex(),
    resultSpend: resultSpend === null ? 'success' : resultSpend
  });
})();
