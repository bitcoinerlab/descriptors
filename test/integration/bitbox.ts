// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/*
BitBox real-device integration test.

This test uses the browser-oriented `bitbox-api` package from Node through
BitBoxBridge. It is intentionally not part of normal CI or `npm test`.

To run:

1. Install dependencies with `npm install`.
2. Build the project with `npm run build`.
3. Ensure that you are running a Bitcoin regtest node and have set up this
   Express-based bitcoind manager: https://github.com/bitcoinjs/regtest-server
   running on 127.0.0.1:8080.
4. Install and start BitBoxBridge.
5. Connect and unlock a BitBox02.
6. Run `npm run test:integration:bitbox`.

The test spends one standard wpkh output and one P2WSH Miniscript output
co-signed with a software wallet using the same policy shape as the Ledger
integration test.

The local chain is regtest, but BitBox Bitcoin API calls use the testnet
signing context internally for all non-mainnet Bitcoin networks. This mirrors
Ledger's use of the Bitcoin Test app for regtest: PSBT scripts are
network-neutral, while hardware wallets usually expose stable testnet support
rather than production regtest signing flows.
*/

console.log(
  'BitBox integration tests: 1 wpkh input + 1 miniscript input (co-signed with a software wallet) -> regtest spends'
);

import * as ecc from '@bitcoinerlab/secp256k1';
import { compilePolicy, ready } from '@bitcoinerlab/miniscript-policies';
import { RegtestUtils } from 'regtest-client';
import { DescriptorsFactory, keyExpressionBIP32, networks } from '../../dist';
import { createBitcoinjsLib } from '../../dist/bitcoinjs';
import { signBIP32 } from '../../dist/signers';
import {
  connectors,
  getVersion,
  getXpub,
  keyExpression,
  registerWallet,
  scriptExpressions,
  signers,
  type BitBoxClient,
  type Manager
} from '../../dist/bitbox';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { encode: olderEncode } = require('bip68');
import {
  createPsbt,
  psbtAddOutput,
  psbtToBase64,
  psbtToHex,
  psbtToTxId
} from '../helpers/psbt';
import { createMasterNode } from '../helpers/keys';

const globalWithBrowserBits = globalThis as Record<string, unknown>;
let localStorageShim = globalWithBrowserBits['localStorage'];
if (globalWithBrowserBits['localStorage'] === undefined) {
  const storage = new Map<string, string>();
  localStorageShim = {
    get length() {
      return storage.size;
    },
    clear() {
      storage.clear();
    },
    getItem(key: string) {
      return storage.get(key) ?? null;
    },
    key(index: number) {
      return [...storage.keys()][index] ?? null;
    },
    removeItem(key: string) {
      storage.delete(key);
    },
    setItem(key: string, value: string) {
      storage.set(key, String(value));
    }
  };
  globalWithBrowserBits['localStorage'] = localStorageShim;
}
if (globalWithBrowserBits['window'] === undefined)
  globalWithBrowserBits['window'] = globalThis;
if (globalWithBrowserBits['self'] === undefined)
  globalWithBrowserBits['self'] = globalThis;
if (globalWithBrowserBits['Window'] === undefined)
  globalWithBrowserBits['Window'] = Object;
(globalWithBrowserBits['window'] as Record<string, unknown>)['localStorage'] =
  localStorageShim;
if (globalWithBrowserBits['WebSocket'] === undefined) {
  // bitbox-api expects a browser WebSocket. For Node + BitBoxBridge, provide one.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  globalWithBrowserBits['WebSocket'] = require('ws');
}

const regtestUtils = new RegtestUtils();
const { Output } = DescriptorsFactory(createBitcoinjsLib(ecc));

const NETWORK = networks.regtest;
const UTXO_VALUE = 2e4;
const FEE = 1000;
const BLOCKS = 5;
const OLDER = olderEncode({ blocks: BLOCKS });
const PREIMAGE =
  '107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f';
const SHA256_DIGEST =
  '6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333';

const POLICY = `and(and(and(pk(@bitbox),pk(@soft)),older(${OLDER})),sha256(${SHA256_DIGEST}))`;
const ORIGIN_PATH = "/84'/1'/0'";
const POLICY_ORIGIN_PATH = "/48'/1'/0'/2'";
const POLICY_RECEIVE_INDEX = 0;
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

(async () => {
  await ready;
  const manager: Manager = await connectors.bridge({
    Output,
    network: NETWORK,
    onClose: () => {
      console.log('BitBox02 connection closed');
    },
    onPairingCode: pairingCode => {
      console.log(`Pairing code:\n${pairingCode}`);
      console.log('Confirm the pairing code on the BitBox02.');
    }
  });

  const version = await getVersion({ manager });
  const xpub = await getXpub({ manager, originPath: ORIGIN_PATH });
  console.log({ version, originPath: ORIGIN_PATH, xpub });

  const standardPsbt = createPsbt(false, NETWORK);
  const standardFinalAddress = regtestUtils.RANDOM_ADDRESS;
  const standardDescriptor = await scriptExpressions.wpkh({
    manager,
    account: 0,
    change: 0,
    index: 0
  });
  const standardOutput = new Output({
    descriptor: standardDescriptor,
    network: NETWORK
  });
  let { txId, vout } = await regtestUtils.faucet(
    standardOutput.getAddress(),
    UTXO_VALUE
  );
  let { txHex } = await regtestUtils.fetch(txId);
  const finalizeStandard = standardOutput.updatePsbtAsInput({
    psbt: standardPsbt,
    txHex,
    vout
  });
  psbtAddOutput(
    standardPsbt,
    {
      address: standardFinalAddress,
      value: BigInt(UTXO_VALUE - FEE)
    },
    NETWORK
  );

  console.log('Sign and broadcast standard wpkh spend');
  await signers.sign({ psbt: standardPsbt, manager });
  finalizeStandard({ psbt: standardPsbt });
  const standardResultSpend = await regtestUtils.broadcast(
    psbtToHex(standardPsbt)
  );
  await regtestUtils.verify({
    txId: psbtToTxId(standardPsbt),
    address: standardFinalAddress,
    vout: 0,
    value: UTXO_VALUE - FEE
  });
  console.log({
    result: standardResultSpend === null ? 'success' : standardResultSpend,
    descriptor: standardDescriptor,
    psbt: psbtToBase64(standardPsbt),
    tx: psbtToHex(standardPsbt)
  });

  const { miniscript, issane }: { miniscript: string; issane: boolean } =
    compilePolicy(POLICY);
  if (!issane) throw new Error(`Error: miniscript not sane`);

  const masterNode = createMasterNode(SOFT_MNEMONIC, NETWORK, false);
  const softKeyExpression = keyExpressionBIP32({
    masterNode,
    originPath: POLICY_ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  const bitboxKeyExpression = await keyExpression({
    manager,
    originPath: POLICY_ORIGIN_PATH,
    change: 0,
    index: '*'
  });
  const miniscriptDescriptor = `wsh(${miniscript
    .replace('@bitbox', bitboxKeyExpression)
    .replace('@soft', softKeyExpression)})`;
  const miniscriptOutput = new Output({
    descriptor: miniscriptDescriptor,
    index: POLICY_RECEIVE_INDEX,
    preimages: [{ digest: `sha256(${SHA256_DIGEST})`, preimage: PREIMAGE }],
    network: NETWORK
  });

  const policyPsbt = createPsbt(false, NETWORK);
  const policyFinalAddress = regtestUtils.RANDOM_ADDRESS;
  ({ txId, vout } = await regtestUtils.faucet(
    miniscriptOutput.getAddress(),
    UTXO_VALUE
  ));
  ({ txHex } = await regtestUtils.fetch(txId));
  const finalizePolicy = miniscriptOutput.updatePsbtAsInput({
    psbt: policyPsbt,
    txHex,
    vout
  });
  psbtAddOutput(
    policyPsbt,
    {
      address: policyFinalAddress,
      value: BigInt(UTXO_VALUE - FEE)
    },
    NETWORK
  );

  console.log('Register Miniscript policy');
  await registerWallet({
    descriptor: miniscriptDescriptor,
    manager,
    policyName: 'BitcoinerLab Regtest'
  });
  console.log('Sign and broadcast Miniscript policy spend');
  await signers.sign({ psbt: policyPsbt, manager });
  signBIP32({ psbt: policyPsbt, masterNode });
  finalizePolicy({ psbt: policyPsbt });

  await regtestUtils.mine(BLOCKS);
  const policyResultSpend = await regtestUtils.broadcast(psbtToHex(policyPsbt));
  await regtestUtils.mine(1);
  await regtestUtils.verify({
    txId: psbtToTxId(policyPsbt),
    address: policyFinalAddress,
    vout: 0,
    value: UTXO_VALUE - FEE
  });

  console.log({
    result: policyResultSpend === null ? 'success' : policyResultSpend,
    descriptor: miniscriptDescriptor,
    psbt: psbtToBase64(policyPsbt),
    tx: psbtToHex(policyPsbt)
  });

  (manager.bitboxClient as BitBoxClient & { close(): void }).close();
})().catch(err => {
  console.error(err);
  process.exit(1);
});
