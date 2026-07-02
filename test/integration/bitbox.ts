// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/*
BitBox real-device smoke test.

This test uses the browser-oriented `bitbox-api` package from Node through
BitBoxBridge. It is intentionally not part of normal CI or `npm test`.

To run:

1. Install dependencies with `npm install`.
2. Build the project with `npm run build`.
3. Install and start BitBoxBridge.
4. Connect and unlock a BitBox02.
5. Run `npm run test:integration:bitbox`.

The test checks version, account xpub retrieval, standard address display and
Miniscript policy registration/address display through this package's BitBox
adapter.
*/

console.log(
  'BitBox integration tests: version + xpub + standard and Miniscript address display'
);

import * as ecc from '@bitcoinerlab/secp256k1';
import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { DescriptorsFactory, networks } from '../../dist';
import { createBitcoinjsLib } from '../../dist/bitcoinjs';
import {
  displayAddress,
  getVersion,
  getXpub,
  keyExpression,
  registerWallet,
  type BitBoxClient,
  type Manager
} from '../../dist/bitbox';
import { compilePolicy, ready } from '@bitcoinerlab/miniscript-policies';

type BitBoxApiModule = {
  bitbox02ConnectBridge(onCloseCb?: () => void): Promise<{
    unlockAndPair(): Promise<{
      getPairingCode(): string | undefined;
      waitConfirm(): Promise<BitBoxClient & { close(): void }>;
    }>;
  }>;
};

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

const importBitBoxApi = new Function(
  'specifier',
  'return import(specifier)'
) as (specifier: string) => Promise<BitBoxApiModule>;

const { Output } = DescriptorsFactory(createBitcoinjsLib(ecc));
const NETWORK = networks.bitcoin;
const ORIGIN_PATH = "/84'/0'/0'";
const POLICY_ORIGIN_PATH = "/48'/0'/0'/2'";

async function waitForPairingConfirmation(pairingCode: string): Promise<void> {
  const rl = createInterface({ input, output });
  try {
    console.log(`Pairing code:\n${pairingCode}`);
    await rl.question(
      'Confirm the pairing code on the BitBox02, then press Enter here.'
    );
  } finally {
    rl.close();
  }
}

(async () => {
  await ready;
  const { bitbox02ConnectBridge } = await importBitBoxApi('bitbox-api');
  const unpaired = await bitbox02ConnectBridge(() => {
    console.log('BitBox02 connection closed');
  });
  const pairing = await unpaired.unlockAndPair();
  const pairingCode = pairing.getPairingCode();
  if (pairingCode) await waitForPairingConfirmation(pairingCode);
  const bitboxClient = await pairing.waitConfirm();

  const manager: Manager = {
    bitboxClient,
    bitboxState: {},
    Output,
    network: NETWORK
  };

  const version = await getVersion({ manager });
  const xpub = await getXpub({
    manager,
    originPath: ORIGIN_PATH,
    display: false
  });

  console.log({ version, originPath: ORIGIN_PATH, xpub });

  const key = await keyExpression({
    manager,
    originPath: ORIGIN_PATH,
    keyPath: '/0/*'
  });
  const descriptor = `wpkh(${key})`;
  const address = await displayAddress({
    descriptor,
    manager,
    index: 0
  });
  console.log({ descriptor, address });

  const { miniscript, issane } = compilePolicy('and(pk(@bitbox),older(5))');
  if (!issane) throw new Error('Compiled BitBox policy is not sane');
  const policyKey = await keyExpression({
    manager,
    originPath: POLICY_ORIGIN_PATH,
    keyPath: '/0/*'
  });
  const policyDescriptor = `wsh(${miniscript.replace('@bitbox', policyKey)})`;
  await registerWallet({
    descriptor: policyDescriptor,
    manager,
    policyName: 'BitcoinerLab'
  });
  const policyAddress = await displayAddress({
    descriptor: policyDescriptor,
    manager,
    index: 0
  });
  console.log({ policyDescriptor, policyAddress });

  bitboxClient.close();
})().catch(err => {
  console.error(err);
  process.exit(1);
});
