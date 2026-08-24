// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

// This file tests the deprecated root LedgerManager/ecc API. Delete the file
// with that compatibility layer in v4.

import * as ecc from '@bitcoinerlab/secp256k1';
import type { LedgerManager } from '../packages/descriptors/dist';

jest.mock(
  '@bitcoinerlab/descriptors-core',
  () => jest.requireActual('../dist'),
  { virtual: true }
);
jest.mock(
  '@bitcoinerlab/descriptors-core/bitcoinjs',
  () => jest.requireActual('../dist/bitcoinjs'),
  { virtual: true }
);
jest.mock(
  '@bitcoinerlab/descriptors-core/ledger',
  () => jest.requireActual('../dist/ledger'),
  { virtual: true }
);
jest.mock('@ledgerhq/ledger-bitcoin', () => ({
  WalletPolicy: class {
    constructor(
      readonly name: string,
      readonly descriptorTemplate: string,
      readonly keys: readonly string[]
    ) {}
  }
}));

const { BIP32, DescriptorsFactory, ledger, networks } = jest.requireActual<
  typeof import('../packages/descriptors/dist')
>('../packages/descriptors/dist');

test('uses root ledgerManager.ecc only for deprecated policy helpers', async () => {
  let isPointCalls = 0;
  const trackedEcc = {
    ...ecc,
    isPoint(point: Uint8Array) {
      isPointCalls += 1;
      return ecc.isPoint(point);
    }
  } satisfies typeof ecc;
  const master = BIP32.fromSeed(new Uint8Array(32).fill(31), networks.regtest);
  const fingerprint = Buffer.from(master.fingerprint).toString('hex');
  const accountXpub = master.derivePath("m/48'/1'/0'").neutered().toBase58();
  const descriptor = `wsh(and_v(v:pk([${fingerprint}/48'/1'/0']${accountXpub}/0/*),older(5)))`;
  const registerWallet = jest.fn(
    async () =>
      [Uint8Array.from([1, 2, 3, 4]), Uint8Array.from([5, 6, 7, 8])] as const
  );
  const ledgerClient = {
    getAppAndVersion: jest.fn(async () => ({
      name: 'Bitcoin Test',
      version: '2.1.0',
      flags: 0
    })),
    getMasterFingerprint: jest.fn(async () => fingerprint),
    getExtendedPubkey: jest.fn(async () => accountXpub),
    registerWallet,
    getWalletAddress: jest.fn(async () => 'bcrt1test'),
    signPsbt: jest.fn(async () => [])
  } as unknown as LedgerManager['ledgerClient'];
  const ledgerManager = {
    ledgerClient,
    ledgerState: { masterFingerprint: master.fingerprint },
    network: networks.regtest,
    ecc: trackedEcc
  } satisfies LedgerManager;

  try {
    await expect(
      ledger.getLedgerMasterFingerPrint({ ledgerManager })
    ).resolves.toEqual(master.fingerprint);
    expect(isPointCalls).toBe(0);

    await ledger.registerLedgerWallet({
      descriptor,
      ledgerManager,
      policyName: 'Root ecc policy'
    });

    expect(isPointCalls).toBeGreaterThan(0);
    expect(registerWallet).toHaveBeenCalledTimes(1);
  } finally {
    DescriptorsFactory(ecc);
  }
});
