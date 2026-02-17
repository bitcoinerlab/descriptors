// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks, Psbt } from 'bitcoinjs-lib';
import type { BIP32Interface } from 'bip32';
import { AppClient } from '@ledgerhq/ledger-bitcoin';
import { DescriptorsFactory } from '../dist/descriptors';
import type { LedgerManager } from '../dist/ledger';
import {
  ledgerPolicyFromOutput,
  ledgerPolicyFromPsbtInput
} from '../dist/ledger';
import { keyExpressionBIP32 } from '../dist/keyExpressions';
import { toHex } from 'uint8array-tools';

const NETWORK = networks.regtest;
const { Output, BIP32 } = DescriptorsFactory(ecc);

function makeMaster(seed: number): BIP32Interface {
  return BIP32.fromSeed(new Uint8Array(32).fill(seed), NETWORK);
}

function keyRootNoOrigin(masterNode: BIP32Interface): string {
  return masterNode.derivePath("m/48'/1'/0'").neutered().toBase58();
}

function keyExpressionNoOrigin(
  masterNode: BIP32Interface,
  keyPath = '/0/*'
): string {
  return `${keyRootNoOrigin(masterNode)}${keyPath}`;
}

function manyExternalKeys(startSeed: number, count: number): string[] {
  return Array.from({ length: count }, (_, index) =>
    keyExpressionNoOrigin(makeMaster(startSeed + index))
  );
}

function mockLedgerManager(masterFingerprint: Uint8Array): LedgerManager {
  const ledgerClient = Object.create(AppClient.prototype) as InstanceType<
    typeof AppClient
  >;
  return {
    ledgerClient,
    ledgerState: { masterFingerprint },
    ecc,
    network: NETWORK
  };
}

function keyRootWithOrigin(masterNode: BIP32Interface): string {
  return `[${toHex(masterNode.fingerprint)}/48'/1'/0']${keyRootNoOrigin(
    masterNode
  )}`;
}

function buildWitnessPsbt({
  scriptPubKey,
  bip32Derivation,
  tapBip32Derivation
}: {
  scriptPubKey: Uint8Array;
  bip32Derivation?: {
    masterFingerprint: Uint8Array;
    path: string;
    pubkey: Uint8Array;
  };
  tapBip32Derivation?: {
    masterFingerprint: Uint8Array;
    path: string;
    pubkey: Uint8Array;
    leafHashes: Uint8Array[];
  };
}): Psbt {
  const psbt = new Psbt({ network: NETWORK });
  psbt.addInput({
    hash: new Uint8Array(32),
    index: 0,
    witnessUtxo: {
      script: scriptPubKey,
      value: 50_000n
    }
  });

  const input = psbt.data.inputs[0];
  if (!input) throw new Error('psbt input not created');
  if (bip32Derivation !== undefined) input.bip32Derivation = [bip32Derivation];
  if (tapBip32Derivation !== undefined)
    input.tapBip32Derivation = [tapBip32Derivation];

  return psbt;
}

describe('ledger policy templates preserve sorted expressions', () => {
  test('preserves sortedmulti(...) in wsh policy templates', async () => {
    const ledgerMaster = makeMaster(101);
    const otherMaster = makeMaster(102);

    const ledgerKey = keyExpressionBIP32({
      masterNode: ledgerMaster,
      originPath: "/48'/1'/0'",
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionNoOrigin(otherMaster);

    const output = new Output({
      descriptor: `wsh(sortedmulti(1,${ledgerKey},${otherKey}))`,
      index: 0,
      network: NETWORK
    });

    const result = await ledgerPolicyFromOutput({
      output,
      ledgerManager: mockLedgerManager(ledgerMaster.fingerprint)
    });
    if (!result) throw new Error('expected a ledger policy');

    expect(result.ledgerTemplate).toEqual('wsh(sortedmulti(1,@0/**,@1/**))');
    expect(result.keyRoots.length).toBe(2);
  });

  test('preserves sortedmulti_a(...) in tr script-path policy templates', async () => {
    const ledgerMaster = makeMaster(111);
    const otherMaster = makeMaster(112);
    const internalMaster = makeMaster(113);

    const ledgerKey = keyExpressionBIP32({
      masterNode: ledgerMaster,
      originPath: "/48'/1'/0'",
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionNoOrigin(otherMaster);
    const internalKey = keyExpressionNoOrigin(internalMaster);

    const output = new Output({
      descriptor: `tr(${internalKey},sortedmulti_a(1,${otherKey},${ledgerKey}))`,
      index: 0,
      network: NETWORK
    });

    const result = await ledgerPolicyFromOutput({
      output,
      ledgerManager: mockLedgerManager(ledgerMaster.fingerprint)
    });
    if (!result) throw new Error('expected a ledger policy');

    expect(result.ledgerTemplate).toEqual(
      'tr(@0/**,sortedmulti_a(1,@1/**,@2/**))'
    );
    expect(result.keyRoots.length).toBe(3);
  });

  test('handles sortedmulti(...) placeholders with 10+ keys', async () => {
    const ledgerMaster = makeMaster(201);
    const ledgerKey = keyExpressionBIP32({
      masterNode: ledgerMaster,
      originPath: "/48'/1'/0'",
      keyPath: '/0/*'
    });
    const otherKeys = manyExternalKeys(202, 10);

    const output = new Output({
      descriptor: `wsh(sortedmulti(1,${[ledgerKey, ...otherKeys].join(',')}))`,
      index: 0,
      network: NETWORK
    });

    const result = await ledgerPolicyFromOutput({
      output,
      ledgerManager: mockLedgerManager(ledgerMaster.fingerprint)
    });
    if (!result) throw new Error('expected a ledger policy');

    expect(result.ledgerTemplate.startsWith('wsh(sortedmulti(1,')).toBe(true);
    expect(result.ledgerTemplate).not.toContain('/**/**');
    expect(result.ledgerTemplate).not.toMatch(/@\d+\/\*\*\d/);

    for (let index = 0; index <= 10; index++) {
      const placeholderRegex = new RegExp(`@${index}/\\*\\*`, 'g');
      const matches = result.ledgerTemplate.match(placeholderRegex) ?? [];
      expect(matches.length).toBe(1);
    }
    expect(result.keyRoots.length).toBe(11);
  });

  test('handles sortedmulti_a(...) placeholders with 10+ keys', async () => {
    const ledgerMaster = makeMaster(221);
    const internalMaster = makeMaster(222);
    const ledgerKey = keyExpressionBIP32({
      masterNode: ledgerMaster,
      originPath: "/48'/1'/0'",
      keyPath: '/0/*'
    });
    const internalKey = keyExpressionNoOrigin(internalMaster);
    const otherKeys = manyExternalKeys(223, 10);

    const output = new Output({
      descriptor: `tr(${internalKey},sortedmulti_a(1,${[
        ...otherKeys,
        ledgerKey
      ].join(',')}))`,
      index: 0,
      network: NETWORK
    });

    const result = await ledgerPolicyFromOutput({
      output,
      ledgerManager: mockLedgerManager(ledgerMaster.fingerprint)
    });
    if (!result) throw new Error('expected a ledger policy');

    expect(result.ledgerTemplate.startsWith('tr(@0/**,sortedmulti_a(1,')).toBe(
      true
    );
    expect(result.ledgerTemplate).not.toContain('/**/**');
    expect(result.ledgerTemplate).not.toMatch(/@\d+\/\*\*\d/);

    for (let index = 0; index <= 11; index++) {
      const placeholderRegex = new RegExp(`@${index}/\\*\\*`, 'g');
      const matches = result.ledgerTemplate.match(placeholderRegex) ?? [];
      expect(matches.length).toBe(1);
    }
    expect(result.keyRoots.length).toBe(12);
  });

  test('ledgerPolicyFromPsbtInput matches repeated tuples for sortedmulti', async () => {
    const ledgerMaster = makeMaster(241);
    const otherMaster = makeMaster(242);

    const ledgerKeyAtIndex = keyExpressionBIP32({
      masterNode: ledgerMaster,
      originPath: "/48'/1'/0'",
      keyPath: '/0/7'
    });
    const otherKeyAtIndex = keyExpressionNoOrigin(otherMaster, '/0/7');

    const output = new Output({
      descriptor: `wsh(sortedmulti(1,${ledgerKeyAtIndex},${otherKeyAtIndex}))`,
      network: NETWORK
    });

    const psbt = buildWitnessPsbt({
      scriptPubKey: output.getScriptPubKey(),
      bip32Derivation: {
        masterFingerprint: ledgerMaster.fingerprint,
        path: "m/48'/1'/0'/0/7",
        pubkey: ledgerMaster.derivePath("m/48'/1'/0'/0/7").publicKey
      }
    });

    const ledgerManager = mockLedgerManager(ledgerMaster.fingerprint);
    ledgerManager.ledgerState.policies = [
      {
        ledgerTemplate: 'wsh(sortedmulti(1,@0/**,@1/**))',
        keyRoots: [
          keyRootWithOrigin(ledgerMaster),
          keyRootNoOrigin(otherMaster)
        ]
      }
    ];

    const policy = await ledgerPolicyFromPsbtInput({
      ledgerManager,
      psbt,
      index: 0
    });

    expect(policy?.ledgerTemplate).toEqual('wsh(sortedmulti(1,@0/**,@1/**))');
    expect(policy?.keyRoots).toEqual([
      keyRootWithOrigin(ledgerMaster),
      keyRootNoOrigin(otherMaster)
    ]);
  });

  test('ledgerPolicyFromPsbtInput matches repeated tuples for sortedmulti_a', async () => {
    const ledgerMaster = makeMaster(251);
    const otherMaster = makeMaster(252);
    const internalMaster = makeMaster(253);

    const ledgerKeyAtIndex = keyExpressionBIP32({
      masterNode: ledgerMaster,
      originPath: "/48'/1'/0'",
      keyPath: '/0/5'
    });
    const otherKeyAtIndex = keyExpressionNoOrigin(otherMaster, '/0/5');
    const internalKeyAtIndex = keyExpressionNoOrigin(internalMaster, '/0/5');

    const output = new Output({
      descriptor: `tr(${internalKeyAtIndex},sortedmulti_a(1,${otherKeyAtIndex},${ledgerKeyAtIndex}))`,
      network: NETWORK
    });

    const xonlyLedgerPubkey = ledgerMaster
      .derivePath("m/48'/1'/0'/0/5")
      .publicKey.slice(1, 33);

    const psbt = buildWitnessPsbt({
      scriptPubKey: output.getScriptPubKey(),
      tapBip32Derivation: {
        masterFingerprint: ledgerMaster.fingerprint,
        path: "m/48'/1'/0'/0/5",
        pubkey: xonlyLedgerPubkey,
        leafHashes: []
      }
    });

    const ledgerManager = mockLedgerManager(ledgerMaster.fingerprint);
    ledgerManager.ledgerState.policies = [
      {
        ledgerTemplate: 'tr(@0/**,sortedmulti_a(1,@1/**,@2/**))',
        keyRoots: [
          keyRootNoOrigin(internalMaster),
          keyRootNoOrigin(otherMaster),
          keyRootWithOrigin(ledgerMaster)
        ]
      }
    ];

    const policy = await ledgerPolicyFromPsbtInput({
      ledgerManager,
      psbt,
      index: 0
    });

    expect(policy?.ledgerTemplate).toEqual(
      'tr(@0/**,sortedmulti_a(1,@1/**,@2/**))'
    );
    expect(policy?.keyRoots).toEqual([
      keyRootNoOrigin(internalMaster),
      keyRootNoOrigin(otherMaster),
      keyRootWithOrigin(ledgerMaster)
    ]);
  });
});
