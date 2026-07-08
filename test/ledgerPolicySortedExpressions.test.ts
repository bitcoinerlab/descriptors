// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

// This test inspects bitcoinjs-lib's BIP174 PSBT internals (tapBip32Derivation)
// which are not available in @scure/btc-signer.
const isScure = process.env['BITCOIN_LIB'] === 'scure';

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks, Psbt } from 'bitcoinjs-lib';
import type { BIP32InterfaceLike } from '../dist/bitcoinLib';
import { AppClient } from '@ledgerhq/ledger-bitcoin';
import { DescriptorsFactory } from '../dist/descriptors';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import {
  displayAddress,
  getVersion,
  signers,
  signMessage,
  type LedgerSession
} from '../dist/ledger/index';
import {
  derivePolicyFromOutput,
  policyForPsbtInput
} from '../dist/hww/policies';
import type { HWWPolicy, HWWPolicyResolver } from '../dist/hww/types';
import { keyExpressionBIP32 } from '../dist/keyExpressions';
import { fromHex, fromUtf8, toBase64, toHex } from 'uint8array-tools';

const NETWORK = networks.regtest;
const { Output, BIP32 } = DescriptorsFactory(createBitcoinjsLib(ecc));

function makeMaster(seed: number): BIP32InterfaceLike {
  return BIP32.fromSeed(new Uint8Array(32).fill(seed), NETWORK);
}

function keyRootNoOrigin(masterNode: BIP32InterfaceLike): string {
  return masterNode.derivePath("m/48'/1'/0'").neutered().toBase58();
}

function keyExpressionNoOrigin(
  masterNode: BIP32InterfaceLike,
  keyPath = '/0/*'
): string {
  return `${keyRootNoOrigin(masterNode)}${keyPath}`;
}

function manyExternalKeys(startSeed: number, count: number): string[] {
  return Array.from({ length: count }, (_, index) =>
    keyExpressionNoOrigin(makeMaster(startSeed + index))
  );
}

function mockLedgerSession(masterFingerprint: Uint8Array): LedgerSession {
  const ledgerClient = Object.create(AppClient.prototype) as InstanceType<
    typeof AppClient
  >;
  return {
    client: ledgerClient,
    store: { masterFingerprint: toHex(masterFingerprint) },
    Output,
    network: NETWORK
  };
}

function mockPolicyResolver({
  masterFingerprint,
  knownPolicies
}: {
  masterFingerprint: Uint8Array;
  knownPolicies?: HWWPolicy[];
}): HWWPolicyResolver {
  return {
    Output,
    network: NETWORK,
    ...(knownPolicies !== undefined ? { knownPolicies } : {}),
    getMasterFingerprint: async () => masterFingerprint,
    getAccountXpub: async () => {
      throw new Error('unexpected standard policy xpub request');
    }
  };
}

function keyRootWithOrigin(masterNode: BIP32InterfaceLike): string {
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

// Skip all tests when using scure backend (tests PSBT internals)
const describeIfNotScure = isScure ? describe.skip : describe;

describeIfNotScure(
  'ledger policy templates preserve sorted expressions',
  () => {
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

      const result = await derivePolicyFromOutput({
        output,
        policyResolver: mockPolicyResolver({
          masterFingerprint: ledgerMaster.fingerprint
        })
      });
      if (!result) throw new Error('expected a ledger policy');

      expect(result.descriptorTemplate).toEqual(
        'wsh(sortedmulti(1,@0/**,@1/**))'
      );
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

      const result = await derivePolicyFromOutput({
        output,
        policyResolver: mockPolicyResolver({
          masterFingerprint: ledgerMaster.fingerprint
        })
      });
      if (!result) throw new Error('expected a ledger policy');

      expect(result.descriptorTemplate).toEqual(
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

      const result = await derivePolicyFromOutput({
        output,
        policyResolver: mockPolicyResolver({
          masterFingerprint: ledgerMaster.fingerprint
        })
      });
      if (!result) throw new Error('expected a ledger policy');

      expect(result.descriptorTemplate.startsWith('wsh(sortedmulti(1,')).toBe(
        true
      );
      expect(result.descriptorTemplate).not.toContain('/**/**');
      expect(result.descriptorTemplate).not.toMatch(/@\d+\/\*\*\d/);

      for (let index = 0; index <= 10; index++) {
        const placeholderRegex = new RegExp(`@${index}/\\*\\*`, 'g');
        const matches = result.descriptorTemplate.match(placeholderRegex) ?? [];
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

      const result = await derivePolicyFromOutput({
        output,
        policyResolver: mockPolicyResolver({
          masterFingerprint: ledgerMaster.fingerprint
        })
      });
      if (!result) throw new Error('expected a ledger policy');

      expect(
        result.descriptorTemplate.startsWith('tr(@0/**,sortedmulti_a(1,')
      ).toBe(true);
      expect(result.descriptorTemplate).not.toContain('/**/**');
      expect(result.descriptorTemplate).not.toMatch(/@\d+\/\*\*\d/);

      for (let index = 0; index <= 11; index++) {
        const placeholderRegex = new RegExp(`@${index}/\\*\\*`, 'g');
        const matches = result.descriptorTemplate.match(placeholderRegex) ?? [];
        expect(matches.length).toBe(1);
      }
      expect(result.keyRoots.length).toBe(12);
    });

    test('policyForPsbtInput matches repeated tuples for sortedmulti', async () => {
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

      const knownPolicies = [
        {
          descriptorTemplate: 'wsh(sortedmulti(1,@0/**,@1/**))',
          keyRoots: [
            keyRootWithOrigin(ledgerMaster),
            keyRootNoOrigin(otherMaster)
          ]
        }
      ];

      const policy = await policyForPsbtInput({
        policyResolver: mockPolicyResolver({
          masterFingerprint: ledgerMaster.fingerprint,
          knownPolicies
        }),
        psbt,
        index: 0
      });

      expect(policy?.descriptorTemplate).toEqual(
        'wsh(sortedmulti(1,@0/**,@1/**))'
      );
      expect(policy?.keyRoots).toEqual([
        keyRootWithOrigin(ledgerMaster),
        keyRootNoOrigin(otherMaster)
      ]);
    });

    test('policyForPsbtInput matches repeated tuples for sortedmulti_a', async () => {
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

      const knownPolicies = [
        {
          descriptorTemplate: 'tr(@0/**,sortedmulti_a(1,@1/**,@2/**))',
          keyRoots: [
            keyRootNoOrigin(internalMaster),
            keyRootNoOrigin(otherMaster),
            keyRootWithOrigin(ledgerMaster)
          ]
        }
      ];

      const policy = await policyForPsbtInput({
        policyResolver: mockPolicyResolver({
          masterFingerprint: ledgerMaster.fingerprint,
          knownPolicies
        }),
        psbt,
        index: 0
      });

      expect(policy?.descriptorTemplate).toEqual(
        'tr(@0/**,sortedmulti_a(1,@1/**,@2/**))'
      );
      expect(policy?.keyRoots).toEqual([
        keyRootNoOrigin(internalMaster),
        keyRootNoOrigin(otherMaster),
        keyRootWithOrigin(ledgerMaster)
      ]);
    });

    test('signs registered policies using policyHmac without requiring policyId', async () => {
      const ledgerMaster = makeMaster(261);
      const otherMaster = makeMaster(262);
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
      const policyHmac = '00112233445566778899aabbccddeeff';
      const session = mockLedgerSession(ledgerMaster.fingerprint);
      session.store.policies = [
        {
          name: 'No id policy',
          descriptorTemplate: 'wsh(sortedmulti(1,@0/**,@1/**))',
          keyRoots: [
            keyRootWithOrigin(ledgerMaster),
            keyRootNoOrigin(otherMaster)
          ],
          policyHmac
        }
      ];
      Object.assign(session.client, {
        signPsbt: jest.fn(async () => [
          [
            0,
            {
              pubkey: ledgerMaster.derivePath("m/48'/1'/0'/0/7").publicKey,
              signature: new Uint8Array([1])
            }
          ]
        ])
      });
      const updateInput = jest.fn();
      const psbt = {
        data: {
          inputs: [
            {
              witnessUtxo: {
                script: output.getScriptPubKey(),
                value: 50_000n
              },
              bip32Derivation: [
                {
                  masterFingerprint: ledgerMaster.fingerprint,
                  path: "m/48'/1'/0'/0/7",
                  pubkey: ledgerMaster.derivePath("m/48'/1'/0'/0/7").publicKey
                }
              ]
            }
          ]
        },
        txInputs: [],
        toBase64: () => 'psbt-base64',
        updateInput
      } as unknown as Psbt;

      await signers.sign({ psbt, session });

      expect(session.client.signPsbt).toHaveBeenCalledWith(
        'psbt-base64',
        expect.objectContaining({ name: 'No id policy' }),
        fromHex(policyHmac)
      );
      expect(updateInput).toHaveBeenCalledWith(0, {
        partialSig: [
          {
            pubkey: ledgerMaster.derivePath("m/48'/1'/0'/0/7").publicKey,
            signature: new Uint8Array([1])
          }
        ]
      });
    });

    test('displays standard addresses through Ledger getWalletAddress', async () => {
      const ledgerMaster = makeMaster(271);
      const ledgerKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/0/*'
      });
      const session = mockLedgerSession(ledgerMaster.fingerprint);
      Object.assign(session.client, {
        getWalletAddress: jest.fn(async () => 'bcrt1ledger')
      });

      await expect(
        displayAddress({
          descriptor: `wpkh(${ledgerKey})`,
          session,
          change: 0,
          index: 3
        })
      ).resolves.toBe('bcrt1ledger');

      expect(session.client.getWalletAddress).toHaveBeenCalledWith(
        expect.any(Object),
        null,
        0,
        3,
        true
      );
    });

    test('gets Ledger app version and signs messages', async () => {
      const ledgerMaster = makeMaster(272);
      const ledgerKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/0/*'
      });
      const signature = new Uint8Array(65).fill(9);
      const session = mockLedgerSession(ledgerMaster.fingerprint);
      Object.assign(session.client, {
        getAppAndVersion: jest.fn(async () => ({
          name: 'Bitcoin Test',
          version: '2.4.0',
          flags: 0
        })),
        signMessage: jest.fn(async () => toBase64(signature))
      });

      await expect(getVersion({ session })).resolves.toBe('2.4.0');
      await expect(
        signMessage({
          session,
          message: 'hello',
          descriptor: `wpkh(${ledgerKey})`,
          change: 0,
          index: 0
        })
      ).resolves.toEqual(signature);
      expect(session.client.signMessage).toHaveBeenCalledWith(
        fromUtf8('hello'),
        "m/84'/1'/0'/0/0"
      );
    });

    test('rejects unsupported Ledger message-signing descriptors before calling the device', async () => {
      const ledgerMaster = makeMaster(273);
      const ledgerKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/86'/1'/0'",
        keyPath: '/0/*'
      });
      const session = mockLedgerSession(ledgerMaster.fingerprint);
      Object.assign(session.client, {
        signMessage: jest.fn(async () => toBase64(new Uint8Array(65)))
      });

      await expect(
        signMessage({
          session,
          message: 'hello',
          descriptor: `tr(${ledgerKey})`,
          change: 0,
          index: 0
        })
      ).rejects.toThrow(
        'standard single-key pkh, sh(wpkh), and wpkh descriptors'
      );
      expect(session.client.signMessage).not.toHaveBeenCalled();
    });
  }
);
