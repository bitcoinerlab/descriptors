// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/*
To run this test, follow these steps:

1. Clone the `descriptors` repository by running
   `git clone https://github.com/bitcoinerlab/descriptors.git`.

2. Install the necessary dependencies by running `npm install`.

3. Ensure that you are running a Bitcoin regtest node and have set up an Express
   regtest-server (https://github.com/bitcoinjs/regtest-server).
   If you haven't already done so, you can use the following steps
   to install and run a Docker image that has already configured a Bitcoin
   regtest node and the required Express server:

   docker pull junderw/bitcoinjs-regtest-server
   docker run -d -p 127.0.0.1:8080:8080 junderw/bitcoinjs-regtest-server

4. Connect your Ledger device, unlock it, and open the Bitcoin Testnet 2.1 App.

5. You are now ready to run the test.
   Run `npx ts-node test/integration/ledger.ts` to execute the test.

================================================================================

This test will create a set of utxos for a Ledger wallet:
  * 1 pkh output on an internal address in account 0, index 0
  * 1 pkh output on an external address in account 0, index 0
  * 1 wsh output corresponding to a script like this:
    and(and(and(pk(@ledger),pk(@soft)),older(${OLDER})),sha256(${SHA256_DIGEST})),
    which means it can be spent by co-sigining with a Ledger and a software wallet
    after BLOCKS blocks since it was mined and providing a preimage for a certain SHA256_DIGEST
  In the test, the utxos are created, they are funded (each one with INITIAL_VALUE)
  and then they are finally spent (signed and finalizedd) using the Ledger wallet
  and the software wallet
*/

console.log(
  'Ledger integration tests: 2 pkh inputs (one internal & external addresses) + 1 miniscript input (cosigned with a software wallet) -> 1 output'
);
//const Transport = require('@ledgerhq/hw-transport-node-hid').default;
import Transport from '@ledgerhq/hw-transport-node-hid';
import { networks, Psbt, address } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
const { encode: olderEncode } = require('bip68');
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
const OLDER = olderEncode({ blocks: BLOCKS });
const PREIMAGE =
  '107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f';
const SHA256_DIGEST =
  '6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333';

const POLICY = `and(and(and(pk(@ledger),pk(@soft)),older(${OLDER})),sha256(${SHA256_DIGEST}))`;
//Ledger Btc App will require an extra click on "non-standard" paths.
const ORIGIN_PATH = `/69420'/1'/0'`;
const RECEIVE_INDEX = 0;

import * as ecc from '@bitcoinerlab/secp256k1';
import {
  finalizePsbt,
  signers,
  keyExpressionBIP32,
  keyExpressionLedger,
  scriptExpressions,
  DescriptorsFactory,
  DescriptorInterface,
  ledger,
  LedgerState
} from '../../src/';
const { signLedger, signBIP32 } = signers;
const { pkhLedger } = scriptExpressions;
const { registerLedgerWallet, AppClient, assertLedgerApp } = ledger;
const { Descriptor, BIP32 } = DescriptorsFactory(ecc);

import { compilePolicy } from '@bitcoinerlab/miniscript';

//Create the psbt that will spend the pkh and wsh outputs:
const psbt = new Psbt({ network: NETWORK });

//Build the miniscript-based descriptor.
//POLICY will be: 'and(and(and(pk(@ledger),pk(@soft)),older(5)),sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333))'
//and miniscript: 'and_v(v:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333),and_v(and_v(v:pk(@ledger),v:pk(@soft)),older(5)))'
const { miniscript, issane }: { miniscript: string; issane: boolean } =
  compilePolicy(POLICY);
if (!issane) throw new Error(`Error: miniscript not sane`);

let txHex: string;
let txId: string;
let vout: number;
let inputIndex: number;
const psbtInputDescriptors: DescriptorInterface[] = [];


(async () => {
  let transport;
  try {
    transport = await Transport.create(3000, 3000);
  } catch (err) {
    console.warn(
      `Warning: a Ledger device has not been detected. Ledger integration will not be tested.`
    );
    return;
  }
  await assertLedgerApp({transport, name: 'Bitcoin Test', minVersion: '2.1.0'});

  const ledgerClient = new AppClient(transport);
  //The Ledger is stateless. We keep state externally.
  const ledgerState: LedgerState = {};

  //Let's create the utxos. First create a descriptor expression using a Ledger.
  //pkhExternalExpression will be something like this:
  //pkh([1597be92/44'/1'/0']tpubDCxfn3TkomFUmqNzKq5AEDS6VHA7RupajLi38JkahFrNeX3oBGp2C7SVWi5a1kr69M8GpeqnGkgGLdja5m5Xbe7E87PEwR5kM2PWKcSZMoE/0/0)
  const pkhExternalExpression: string = await pkhLedger({
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
  //Fund this address. regtestUtils is communicating with a real regtest node.
  ({ txId, vout } = await regtestUtils.faucet(
    pkhExternalDescriptor.getAddress(),
    INITIAL_VALUE
  ));
  //Retrieve the tx from the mempool:
  txHex = (await regtestUtils.fetch(txId)).txHex;
  //Now add an input to the psbt. updatePsbt would also update timelock (not in this case).
  inputIndex = pkhExternalDescriptor.updatePsbt({ txHex, vout, psbt });
  //Save the descriptor for later, indexed by its psbt input number.
  psbtInputDescriptors[inputIndex] = pkhExternalDescriptor;

  //Repeat the same for another pkh change address;
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

  //Here we create a BIP32 software wallet that we will use to cosign:
  const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);

  //Let's start preparing the wsh output. First create the keyExpressions of
  //the keys that will be used to sign the wsh output.
  //Create a ranged key expression (note the index: *) using the software wallet on a non-standard origin path.
  //We could have also created a non-ranged key expression by providing a number to index.
  //softKeyExpression will be something like this:
  //[73c5da0a/69420'/1'/0']tpubDDB5ZuMuWmdzs7r4h58fwZQ1eYJvziXaLMiAfHYrAev3jFrfLtsYsu7Cp1hji8KcG9z9CcvHe1FfkvpsjbvMd2JTLwFkwXQCYjTZKGy8jWg/0/*
  const softKeyExpression: string = keyExpressionBIP32({
    masterNode,
    originPath: ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  //Create the equivalent ranged key expression using the Ledger wallet.
  //ledgerKeyExpression will be something like this:
  //[1597be92/69420'/1'/0']tpubDCNNkdMMfhdsCFf1uufBVvHeHSEAEMiXydCvxuZKgM2NS3NcRCUP7dxihYVTbyu1H87pWakBynbYugEQcCbpR66xyNRVQRzr1TcTqqsWJsK/0/*
  //Since this is a non-standard origin path, the Ledger will warn the user about this.
  const ledgerKeyExpression: string = await keyExpressionLedger({
    ledgerClient,
    ledgerState,
    originPath: ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  //Now, we prepare the ranged miniscript descriptor expression for external addresses (change = 0).
  //expression will be something like this:
  //wsh(and_v(v:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333),and_v(and_v(v:pk([1597be92/69420'/1'/0']tpubDCNNkdMMfhdsCFf1uufBVvHeHSEAEMiXydCvxuZKgM2NS3NcRCUP7dxihYVTbyu1H87pWakBynbYugEQcCbpR66xyNRVQRzr1TcTqqsWJsK/0/*),v:pk([73c5da0a/69420'/1'/0']tpubDDB5ZuMuWmdzs7r4h58fwZQ1eYJvziXaLMiAfHYrAev3jFrfLtsYsu7Cp1hji8KcG9z9CcvHe1FfkvpsjbvMd2JTLwFkwXQCYjTZKGy8jWg/0/*)),older(5))))
  const expression = `wsh(${miniscript
    .replace('@ledger', ledgerKeyExpression)
    .replace('@soft', softKeyExpression)})`;
  //Get the descriptor for index RECEIVE_INDEX. Here we need to pass the index because
  //we used a range key expressions above
  //We also pass the PREIMAGE so that miniscriptDescriptor will be able to finalize the tx (create the scriptWitness)
  const miniscriptDescriptor = new Descriptor({
    expression,
    index: RECEIVE_INDEX,
    preimages: [{ digest: `sha256(${SHA256_DIGEST})`, preimage: PREIMAGE }],
    network: NETWORK
  });
  const receiveAddress = miniscriptDescriptor.getAddress();
  //Send some BTC to the wsh script address
  ({ txId, vout } = await regtestUtils.faucet(receiveAddress, INITIAL_VALUE));
  txHex = (await regtestUtils.fetch(txId)).txHex;

  //Now add a new input (including bip32 & sequence) & set the tx timelock, if needed.
  //In this case the timelock is not set since this is a relative-timelock script (it sets sequence in the input)
  inputIndex = miniscriptDescriptor.updatePsbt({ txHex, vout, psbt });
  //It is important that they are indexed wrt its psbt input number
  psbtInputDescriptors[inputIndex] = miniscriptDescriptor;

  //This is where we'll send the funds. Just some random address.
  psbt.addOutput({ script: FINAL_SCRIPTPUBKEY, value: FINAL_VALUE });

  //=============
  //Register Ledger policies of non-standard descriptors.
  //Registration is stored in ledgerState and is a necessary step before
  //signing with non-standard policies.
  //registerLedgerWallet internally takes all the necessary stepts to register
  //the generalized Ledger format: a policy template finished with /** and its keyRoots
  //The same registered policy will be used for internal addresses. There will be no
  //need to register it again.
  await registerLedgerWallet({
    descriptor: miniscriptDescriptor,
    policyName: 'BitcoinerLab',
    ledgerClient,
    ledgerState
  });

  //=============
  //Sign the psbt with the Ledger. The relevant wallet policy is automatically
  //retrieved from state by parsing the descriptors of each input and retrieving
  //the wallet policy that can sign it. ALso a Default Policy is automatically
  //constructed when the input is a BIP44,49,84 or 86 type.
  await signLedger({
    psbt,
    descriptors: psbtInputDescriptors,
    ledgerClient,
    ledgerState
  });
  //Now sign the PSBT with the BIP32 node (the software wallet)
  signBIP32({ psbt, masterNode });

  //=============
  //Finalize the psbt:
  //descriptors are indexed wrt its psbt input number:
  //This uses the miniscript satisfier from @bitcoinerlab/miniscript to
  //create the scriptWitness among other things.
  finalizePsbt({ psbt, descriptors: psbtInputDescriptors });

  const spendTx = psbt.extractTransaction();
  //We need to mine BLOCKS in order to be accepted
  await regtestUtils.mine(BLOCKS);
  //Broadcast it
  const resultSpend = await regtestUtils.broadcast(spendTx.toHex());

  //Mine it
  await regtestUtils.mine(1);
  //Verify that the tx was accepted. This will throw if not ok
  await regtestUtils.verify({
    txId: spendTx.getId(),
    address: FINAL_ADDRESS,
    vout: 0,
    value: FINAL_VALUE
  });

  console.log({
    result: resultSpend === null ? 'success' : resultSpend,
    tx: spendTx.toHex()
  });
})();
