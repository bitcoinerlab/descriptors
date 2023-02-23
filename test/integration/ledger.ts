// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/*
This test will create a set of UTXOs for a Ledger wallet:
  * 1 P2PKH output on an internal address, change 1, in account 0, index 0
  * 1 P2PKH output on an external address, change 0, in account 0, index 0
  * 1 P2WSH output corresponding to a script based on this policy:
    and(and(and(pk(@ledger),pk(@soft)),older(${OLDER})),sha256(${SHA256_DIGEST})),
    which means it can be spent by co-signing with a Ledger and a Software
    wallet after BLOCKS blocks since it was mined and providing a preimage for
    a certain SHA256_DIGEST.

In the test, the UTXOs are created, funded (each one with UTXO_VALUE),
and finally spent by co-signing (Ledger + Soft) a partially-signed Bitcoin
Transaction (PSBT), finalizing it and broadcasting it to the network.

================================================================================

To run this test, follow these steps:

1. Clone the `descriptors` repository by running
   `git clone https://github.com/bitcoinerlab/descriptors.git`.

2. Install the necessary dependencies by running `npm install`.

3. Ensure that you are running a Bitcoin regtest node and have set up this
   Express-based bitcoind manager: https://github.com/bitcoinjs/regtest-server
   running on 127.0.0.1:8080.
   You can use the following steps to install and run a Docker image already
   configured with the mentioned services:

   docker pull junderw/bitcoinjs-regtest-server
   docker run -d -p 127.0.0.1:8080:8080 junderw/bitcoinjs-regtest-server

4. Connect your Ledger device, unlock it, and open the Bitcoin Testnet 2.1 App.

5. You are now ready to run the test:
   npx ts-node test/integration/ledger.ts

*/

console.log(
  'Ledger integration tests: 2 pkh inputs (one internal & external addresses) + 1 miniscript input (co-signed with a software wallet) -> 1 output'
);
import Transport from '@ledgerhq/hw-transport-node-hid';
import { networks, Psbt } from 'bitcoinjs-lib';
import { mnemonicToSeedSync } from 'bip39';
const { encode: olderEncode } = require('bip68');
import { RegtestUtils } from 'regtest-client';
const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;

const UTXO_VALUE = 2e4;
const FINAL_ADDRESS = regtestUtils.RANDOM_ADDRESS;
const FEE = 1000;
const BLOCKS = 5;
const OLDER = olderEncode({ blocks: BLOCKS });
const PREIMAGE =
  '107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f';
const SHA256_DIGEST =
  '6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333';

const POLICY = `and(and(and(pk(@ledger),pk(@soft)),older(${OLDER})),sha256(${SHA256_DIGEST}))`;

const WSH_ORIGIN_PATH = `/69420'/1'/0'`; //Actually, this could be any random path. Note that the Ledger will show a warning for non-standardness, though.
const WSH_RECEIVE_INDEX = 0;

const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

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

//Create the psbt that will spend the pkh and wsh outputs and send funds to FINAL_ADDRESS:
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
//In this array, we will keep track of the descriptors of each input:
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
  //Throw if not running Bitcoin Test >= 2.1.0
  await assertLedgerApp({
    transport,
    name: 'Bitcoin Test',
    minVersion: '2.1.0'
  });

  const ledgerClient = new AppClient(transport);
  //The Ledger is stateless. We keep state externally (keeps track of masterFingerprint, xpubs, wallet policies, ...)
  const ledgerState: LedgerState = {};

  //Let's create the utxos. First create a descriptor expression using a Ledger.
  //pkhExternalExpression will be something like this:
  //pkh([1597be92/44'/1'/0']tpubDCxfn3TkomFUmqNzKq5AEDS6VHA7RupajLi38JkahFrNeX3oBGp2C7SVWi5a1kr69M8GpeqnGkgGLdja5m5Xbe7E87PEwR5kM2PWKcSZMoE/0/0)
  const pkhExternalExpression: string = await pkhLedger({
    ledgerClient,
    ledgerState,
    network: NETWORK,
    account: 0,
    change: 0,
    index: 0
  });
  const pkhExternalDescriptor = new Descriptor({
    network: NETWORK,
    expression: pkhExternalExpression
  });
  //Fund this utxo. regtestUtils communicates with the regtest node manager on port 8080.
  ({ txId, vout } = await regtestUtils.faucet(
    pkhExternalDescriptor.getAddress(),
    UTXO_VALUE
  ));
  //Retrieve the tx from the mempool:
  txHex = (await regtestUtils.fetch(txId)).txHex;
  //Now add an input to the psbt. updatePsbt would also update timelock if needed (not in this case).
  inputIndex = pkhExternalDescriptor.updatePsbt({ psbt, txHex, vout });
  //Save the descriptor for later, indexed by its psbt input number.
  psbtInputDescriptors[inputIndex] = pkhExternalDescriptor;

  //Repeat the same for another pkh change address:
  const pkhChangeExpression = await pkhLedger({
    ledgerClient,
    ledgerState,
    network: NETWORK,
    account: 0,
    change: 1,
    index: 0
  });
  const pkhChangeDescriptor = new Descriptor({
    network: NETWORK,
    expression: pkhChangeExpression
  });
  ({ txId, vout } = await regtestUtils.faucet(
    pkhChangeDescriptor.getAddress(),
    UTXO_VALUE
  ));
  txHex = (await regtestUtils.fetch(txId)).txHex;
  inputIndex = pkhChangeDescriptor.updatePsbt({ psbt, txHex, vout });
  psbtInputDescriptors[inputIndex] = pkhChangeDescriptor;

  //Here we create the BIP32 software wallet that will be used to co-sign the 3rd utxo of this test:
  const masterNode = BIP32.fromSeed(mnemonicToSeedSync(SOFT_MNEMONIC), NETWORK);

  //Let's prepare the wsh utxo. First create the Ledger and Soft key expressions
  //that will be used to co-sign the wsh output.
  //First, create a ranged key expression (index: '*') using the software wallet
  //on the WSH_ORIGIN_PATH origin path.
  //We could have also created a non-ranged key expression by providing a number
  //to index.
  //softKeyExpression will be something like this:
  //[73c5da0a/69420'/1'/0']tpubDDB5ZuMuWmdzs7r4h58fwZQ1eYJvziXaLMiAfHYrAev3jFrfLtsYsu7Cp1hji8KcG9z9CcvHe1FfkvpsjbvMd2JTLwFkwXQCYjTZKGy8jWg/0/*
  const softKeyExpression: string = keyExpressionBIP32({
    masterNode,
    originPath: WSH_ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  //Create the equivalent ranged key expression using the Ledger wallet.
  //ledgerKeyExpression will be something like this:
  //[1597be92/69420'/1'/0']tpubDCNNkdMMfhdsCFf1uufBVvHeHSEAEMiXydCvxuZKgM2NS3NcRCUP7dxihYVTbyu1H87pWakBynbYugEQcCbpR66xyNRVQRzr1TcTqqsWJsK/0/*
  //Since WSH_ORIGIN_PATH is a non-standard path, the Ledger will warn the user about this.
  const ledgerKeyExpression: string = await keyExpressionLedger({
    ledgerClient,
    ledgerState,
    originPath: WSH_ORIGIN_PATH,
    change: 0,
    index: '*'
  });

  //Now, we prepare the ranged miniscript descriptor expression for external addresses (change = 0).
  //expression will be something like this:
  //wsh(and_v(v:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333),and_v(and_v(v:pk([1597be92/69420'/1'/0']tpubDCNNkdMMfhdsCFf1uufBVvHeHSEAEMiXydCvxuZKgM2NS3NcRCUP7dxihYVTbyu1H87pWakBynbYugEQcCbpR66xyNRVQRzr1TcTqqsWJsK/0/*),v:pk([73c5da0a/69420'/1'/0']tpubDDB5ZuMuWmdzs7r4h58fwZQ1eYJvziXaLMiAfHYrAev3jFrfLtsYsu7Cp1hji8KcG9z9CcvHe1FfkvpsjbvMd2JTLwFkwXQCYjTZKGy8jWg/0/*)),older(5))))
  const expression = `wsh(${miniscript
    .replace('@ledger', ledgerKeyExpression)
    .replace('@soft', softKeyExpression)})`;
  //Get the descriptor for index WSH_RECEIVE_INDEX. Here we need to pass the index because
  //we used range key expressions above. `index` is only necessary when using range expressions.
  //We also pass the PREIMAGE so that miniscriptDescriptor will be able to finalize the tx later (creating the scriptWitness)
  const miniscriptDescriptor = new Descriptor({
    expression,
    index: WSH_RECEIVE_INDEX,
    preimages: [{ digest: `sha256(${SHA256_DIGEST})`, preimage: PREIMAGE }],
    network: NETWORK
  });
  //We can now fund the wsh utxo:
  ({ txId, vout } = await regtestUtils.faucet(
    miniscriptDescriptor.getAddress(),
    UTXO_VALUE
  ));
  txHex = (await regtestUtils.fetch(txId)).txHex;

  //Now add a the input to the psbt (including bip32 derivation info & sequence) and
  //set the tx timelock, if needed.
  //In this case the timelock won't be set since this is a relative-timelock
  //script (it will set the sequence in the input)
  inputIndex = miniscriptDescriptor.updatePsbt({ psbt, txHex, vout });
  //Save the descriptor, indexed by input index, for later:
  psbtInputDescriptors[inputIndex] = miniscriptDescriptor;

  //Now add an ouput. This is where we'll send the funds. We'll send them to
  //some random address that we don't care about in this test.
  psbt.addOutput({ address: FINAL_ADDRESS, value: UTXO_VALUE * 3 - FEE });

  //=============
  //Register Ledger policies of non-standard descriptors.
  //Registration is stored in ledgerState and is a necessary step before
  //signing with non-standard policies when using a Ledger wallet.
  //registerLedgerWallet internally takes all the necessary steps to register
  //the generalized Ledger format: a policy template finished with /** and its keyRoots.
  //So, even though this wallet policy is created using a descriptor representing
  //an external address, the policy will be used interchangeably with internal
  //and external addresses.
  await registerLedgerWallet({
    ledgerClient,
    ledgerState,
    descriptor: miniscriptDescriptor,
    policyName: 'BitcoinerLab'
  });

  //=============
  //Sign the psbt with the Ledger. The relevant wallet policy is automatically
  //retrieved from state by parsing the descriptors of each input and retrieving
  //the wallet policy that can sign it. Also a Default Policy is automatically
  //constructed when the input is of BIP 44, 49, 84 or 86 type.
  await signLedger({
    ledgerClient,
    ledgerState,
    psbt,
    descriptors: psbtInputDescriptors
  });
  //Now sign the PSBT with the BIP32 node (the software wallet)
  signBIP32({ psbt, masterNode });

  //=============
  //Finalize the psbt:
  //descriptors are indexed wrt its psbt input number.
  //finalizePsbt uses the miniscript satisfier from @bitcoinerlab/miniscript to
  //create the scriptWitness among other things.
  finalizePsbt({ psbt, descriptors: psbtInputDescriptors });

  //Since the miniscript uses a relative-timelock, we need to mine BLOCKS before
  //broadcasting the tx so that it can be accepted by the network
  await regtestUtils.mine(BLOCKS);
  //Broadcast the tx:
  const spendTx = psbt.extractTransaction();
  const resultSpend = await regtestUtils.broadcast(spendTx.toHex());
  //Mine it
  await regtestUtils.mine(1);
  //Verify that the tx was accepted. This will throw if not ok:
  await regtestUtils.verify({
    txId: spendTx.getId(),
    address: FINAL_ADDRESS,
    vout: 0,
    value: UTXO_VALUE * 3 - FEE
  });

  console.log({
    result: resultSpend === null ? 'success' : resultSpend,
    psbt: psbt.toBase64(),
    tx: spendTx.toHex()
  });
})();
