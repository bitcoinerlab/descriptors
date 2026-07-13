// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

// This file tests deprecated LedgerManager.Output compatibility with the Scure
// backend. Delete it with that compatibility layer in v4.

import { HDKey } from '@scure/bip32';
import { fromHex } from 'uint8array-tools';
import { DescriptorsFactory, keyExpressionBIP32, networks } from '../dist';
import { createScureLib } from '../dist/scure';
import {
  registerLedgerWallet,
  type LedgerManager,
  type Session
} from '../dist/ledger';

test('uses a Scure-bound LedgerManager Output for policy registration', async () => {
  const { Output } = DescriptorsFactory(createScureLib());
  const master = HDKey.fromMasterSeed(
    new Uint8Array(32).fill(32),
    networks.regtest.bip32
  );
  const masterFingerprint = fromHex(
    master.fingerprint.toString(16).padStart(8, '0')
  );
  const key = keyExpressionBIP32({
    masterNode: master,
    originPath: "/48'/1'/0'",
    keyPath: '/0/*'
  });
  let outputConstructions = 0;
  class LegacyScureOutput extends Output {
    constructor(options: ConstructorParameters<typeof Output>[0]) {
      super(options);
      outputConstructions += 1;
    }
  }
  const registerWallet = jest.fn(
    async () =>
      [Uint8Array.from([1, 2, 3, 4]), Uint8Array.from([5, 6, 7, 8])] as const
  );
  const ledgerManager: LedgerManager = {
    ledgerClient: { registerWallet } as unknown as Session['client'],
    ledgerState: { masterFingerprint },
    network: networks.regtest,
    Output: LegacyScureOutput
  };

  await registerLedgerWallet({
    descriptor: `wsh(and_v(v:pk(${key}),older(5)))`,
    ledgerManager,
    policyName: 'Scure legacy policy'
  });

  expect(outputConstructions).toBe(1);
  expect(registerWallet).toHaveBeenCalledTimes(1);
});
