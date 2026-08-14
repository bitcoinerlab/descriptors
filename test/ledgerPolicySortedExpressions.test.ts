// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

// This test inspects bitcoinjs-lib's BIP174 PSBT internals (tapBip32Derivation)
// which are not available in @scure/btc-signer.
const isScure = process.env['BITCOIN_LIB'] === 'scure';

import * as ecc from '@bitcoinerlab/secp256k1';
import * as ledgerBitcoinApi from '@ledgerhq/ledger-bitcoin';
import { networks, Psbt } from 'bitcoinjs-lib';
import type { BIP32InterfaceLike } from '../dist/bitcoinLib';
import { DescriptorsFactory } from '../dist/descriptors';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import {
  assertLedgerApp,
  connect,
  displayAddress,
  getLedgerMasterFingerPrint,
  getVersion,
  registerLedgerWallet,
  registerPolicy,
  signers,
  signMessage,
  type LedgerManager,
  type LedgerState,
  type Session
} from '../dist/ledger/index';
import {
  derivePolicyFromOutput,
  policyForPsbtInput
} from '../dist/hww/policies';
import { keyExpressionBIP32 } from '../dist/keyExpressions';
import { fromHex, fromUtf8, toBase64, toHex } from 'uint8array-tools';

type LedgerBitcoinApi = Awaited<
  Parameters<typeof connect>[0]['driver']['bitcoinApi']
>;

const mockHidOpen = jest.fn();
const mockBleOpen = jest.fn();

jest.mock('@ledgerhq/ledger-bitcoin', () => ({
  ...jest.requireActual('@ledgerhq/ledger-bitcoin'),
  AppClient: class {
    async getMasterFingerprint() {
      return 'aabbccdd';
    }
  }
}));

const NETWORK = networks.regtest;
const BITCOIN_API = {
  ...ledgerBitcoinApi,
  AppClient: class {
    async getMasterFingerprint() {
      return 'aabbccdd';
    }
  }
} as unknown as LedgerBitcoinApi;
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

function mockLedgerSession(masterFingerprint: Uint8Array): Session {
  const ledgerClient = {} as Session['client'];
  return {
    client: ledgerClient,
    bitcoinApi: BITCOIN_API,
    store: { masterFingerprint: toHex(masterFingerprint) },
    network: NETWORK,
    close: async () => undefined
  };
}

function mockGetMasterFingerprint(masterFingerprint: Uint8Array) {
  return async () => masterFingerprint;
}

async function unexpectedGetAccountXpub(): Promise<string> {
  throw new Error('unexpected standard policy xpub request');
}

function mockLedgerTransport() {
  return { send: jest.fn(), close: jest.fn() };
}

function ledgerAppTransport({
  name = 'Bitcoin',
  version
}: {
  name?: string;
  version: string;
}) {
  const nameBytes = fromUtf8(name);
  const versionBytes = fromUtf8(version);
  const response = Uint8Array.from([
    1,
    nameBytes.length,
    ...nameBytes,
    versionBytes.length,
    ...versionBytes,
    0
  ]);
  return { send: jest.fn(async () => response) };
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
        getMasterFingerprint: mockGetMasterFingerprint(ledgerMaster.fingerprint)
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
        getMasterFingerprint: mockGetMasterFingerprint(ledgerMaster.fingerprint)
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
        getMasterFingerprint: mockGetMasterFingerprint(ledgerMaster.fingerprint)
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
        getMasterFingerprint: mockGetMasterFingerprint(ledgerMaster.fingerprint)
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
        getMasterFingerprint: mockGetMasterFingerprint(
          ledgerMaster.fingerprint
        ),
        getAccountXpub: unexpectedGetAccountXpub,
        knownPolicies,
        network: NETWORK,
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
        getMasterFingerprint: mockGetMasterFingerprint(
          ledgerMaster.fingerprint
        ),
        getAccountXpub: unexpectedGetAccountXpub,
        knownPolicies,
        network: NETWORK,
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

    test('skips unrelated inputs before requiring UTXO metadata', async () => {
      const ledgerMaster = makeMaster(259);
      const otherMaster = makeMaster(260);
      const getMasterFingerprint = jest.fn(
        async () => ledgerMaster.fingerprint
      );
      const psbt = {
        data: {
          inputs: [
            {},
            {
              bip32Derivation: [
                {
                  masterFingerprint: otherMaster.fingerprint,
                  path: "m/84'/1'/0'/0/0",
                  pubkey: otherMaster.derivePath("m/84'/1'/0'/0/0").publicKey
                }
              ]
            }
          ]
        },
        txInputs: []
      } as unknown as Psbt;
      const params = {
        psbt,
        network: NETWORK,
        getMasterFingerprint,
        getAccountXpub: unexpectedGetAccountXpub
      };

      await expect(
        policyForPsbtInput({ ...params, index: 0 })
      ).resolves.toBeUndefined();
      expect(getMasterFingerprint).not.toHaveBeenCalled();
      await expect(
        policyForPsbtInput({ ...params, index: 1 })
      ).resolves.toBeUndefined();
      expect(getMasterFingerprint).toHaveBeenCalledTimes(1);
    });

    test('requires UTXO metadata for inputs owned by the device', async () => {
      const ledgerMaster = makeMaster(258);
      const psbt = {
        data: {
          inputs: [
            {
              bip32Derivation: [
                {
                  masterFingerprint: ledgerMaster.fingerprint,
                  path: "m/84'/1'/0'/0/0",
                  pubkey: ledgerMaster.derivePath("m/84'/1'/0'/0/0").publicKey
                }
              ]
            }
          ]
        },
        txInputs: []
      } as unknown as Psbt;

      await expect(
        policyForPsbtInput({
          psbt,
          index: 0,
          network: NETWORK,
          getMasterFingerprint: async () => ledgerMaster.fingerprint,
          getAccountXpub: unexpectedGetAccountXpub
        })
      ).rejects.toThrow('Could not retrieve scriptPubKey for input 0');
    });

    test('signs registered policy inputs using policyHmac without requiring policyId', async () => {
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
      const signPsbt = jest.fn(async () => [
        [
          0,
          {
            pubkey: ledgerMaster.derivePath("m/48'/1'/0'/0/7").publicKey,
            signature: new Uint8Array([1])
          }
        ]
      ]);
      Object.assign(session.client, {
        signPsbt
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
            },
            {
              witnessUtxo: {
                script: new Uint8Array([0x51]),
                value: 40_000n
              }
            },
            {
              witnessUtxo: {
                script: new Uint8Array([0x51]),
                value: 30_000n
              },
              bip32Derivation: [
                {
                  masterFingerprint: otherMaster.fingerprint,
                  path: "m/84'/1'/0'/0/0",
                  pubkey: otherMaster.derivePath("m/84'/1'/0'/0/0").publicKey
                }
              ]
            },
            {}
          ]
        },
        txInputs: [],
        toBase64: () => 'psbt-base64',
        updateInput
      } as unknown as Psbt;

      await signers.signInput({ psbt, index: 0, session });

      expect(signPsbt).toHaveBeenCalledWith(
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

      signPsbt.mockClear();
      updateInput.mockClear();
      await signers.sign({ psbt, session });
      expect(signPsbt).toHaveBeenCalledTimes(1);
      expect(updateInput).toHaveBeenCalledWith(0, expect.any(Object));
    });

    test.each(['/**', '/<0;1>/*'])(
      'registers policies from the generalized key path %s',
      async keyPath => {
        const ledgerMaster = makeMaster(281);
        const session = mockLedgerSession(ledgerMaster.fingerprint);
        const registerWallet = jest.fn(async () => [
          fromHex('aabbccdd'),
          fromHex('00112233445566778899aabbccddeeff')
        ]);
        Object.assign(session.client, { registerWallet });
        const ledgerKey = keyExpressionBIP32({
          masterNode: ledgerMaster,
          originPath: "/48'/1'/0'",
          keyPath
        });

        await registerPolicy({
          descriptor: `wsh(and_v(v:pk(${ledgerKey}),older(5)))`,
          session,
          name: 'Generalized policy'
        });

        expect(registerWallet).toHaveBeenCalledTimes(1);
        expect(session.store.policies?.[0]).toMatchObject({
          name: 'Generalized policy',
          descriptorTemplate: 'wsh(and_v(v:pk(@0/**),older(5)))'
        });
      }
    );

    // Remove with LedgerManager.Output compatibility in v4.
    test('uses LedgerManager Output for deprecated policy registration', async () => {
      const ledgerMaster = makeMaster(282);
      let outputConstructions = 0;
      class LegacyOutput extends Output {
        constructor(options: ConstructorParameters<typeof Output>[0]) {
          super(options);
          outputConstructions += 1;
        }
      }
      const registerWallet = jest.fn(async () => [
        fromHex('aabbccdd'),
        fromHex('00112233445566778899aabbccddeeff')
      ]);
      const ledgerManager: LedgerManager = {
        ledgerClient: { registerWallet } as unknown as Session['client'],
        ledgerState: { masterFingerprint: ledgerMaster.fingerprint },
        network: NETWORK,
        Output: LegacyOutput
      };
      const ledgerKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/48'/1'/0'",
        keyPath: '/0/*'
      });

      await registerLedgerWallet({
        descriptor: `wsh(and_v(v:pk(${ledgerKey}),older(5)))`,
        ledgerManager,
        policyName: 'Legacy output policy'
      });

      expect(outputConstructions).toBe(1);
      expect(registerWallet).toHaveBeenCalledTimes(1);
    });

    // Remove with LedgerManager and legacy state migration in v4.
    test('migrates populated 3.x Ledger state before deprecated helpers use it', async () => {
      const ledgerMaster = makeMaster(263);
      const otherMaster = makeMaster(264);
      const ledgerKeyAtIndex = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/48'/1'/0'",
        keyPath: '/0/7'
      });
      const output = new Output({
        descriptor: `wsh(sortedmulti(1,${ledgerKeyAtIndex},${keyExpressionNoOrigin(otherMaster, '/0/7')}))`,
        network: NETWORK
      });
      const descriptorTemplate = 'wsh(sortedmulti(1,@0/**,@1/**))';
      const keyRoots = [
        keyRootWithOrigin(ledgerMaster),
        keyRootNoOrigin(otherMaster)
      ];
      const policyId = fromHex('aabbccdd');
      const policyHmac = fromHex('00112233445566778899aabbccddeeff');
      const ledgerState: LedgerState = {
        masterFingerprint: ledgerMaster.fingerprint,
        policies: [
          {
            policyName: 'Legacy policy',
            ledgerTemplate: descriptorTemplate,
            keyRoots,
            policyId,
            policyHmac
          }
        ],
        xpubs: { "/48'/1'/0'": 'cached-xpub' }
      };
      const ledgerClient = {
        getMasterFingerprint: jest.fn(async () => 'unexpected'),
        signPsbt: jest.fn(async () => [
          [
            0,
            {
              pubkey: ledgerMaster.derivePath("m/48'/1'/0'/0/7").publicKey,
              signature: new Uint8Array([1])
            }
          ]
        ])
      } as unknown as Session['client'];
      let outputConstructions = 0;
      class LegacyOutput extends Output {
        constructor(options: ConstructorParameters<typeof Output>[0]) {
          super(options);
          outputConstructions += 1;
        }
      }
      const ledgerManager: LedgerManager = {
        ledgerClient,
        ledgerState,
        network: NETWORK,
        Output: LegacyOutput
      };
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

      await expect(
        getLedgerMasterFingerPrint({ ledgerManager })
      ).resolves.toEqual(ledgerMaster.fingerprint);
      const normalizedPolicies = ledgerState.policies;
      await signers.signLedger({ psbt, ledgerManager });
      await signers.signInputLedger({ psbt, index: 0, ledgerManager });

      expect(ledgerClient.getMasterFingerprint).not.toHaveBeenCalled();
      expect(outputConstructions).toBe(2);
      expect(ledgerClient.signPsbt).toHaveBeenCalledTimes(2);
      expect(ledgerState).toEqual({
        masterFingerprint: toHex(ledgerMaster.fingerprint),
        policies: [
          {
            name: 'Legacy policy',
            descriptorTemplate,
            keyRoots,
            policyId: toHex(policyId),
            policyHmac: toHex(policyHmac)
          }
        ],
        xpubs: { "/48'/1'/0'": 'cached-xpub' }
      });
      expect(ledgerState.policies).toBe(normalizedPolicies);
      expect(ledgerClient.signPsbt).toHaveBeenCalledWith(
        'psbt-base64',
        expect.objectContaining({ name: 'Legacy policy' }),
        policyHmac
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

    test('displays fixed standard addresses without index', async () => {
      const ledgerMaster = makeMaster(274);
      const ledgerKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/0/3'
      });
      const session = mockLedgerSession(ledgerMaster.fingerprint);
      Object.assign(session.client, {
        getWalletAddress: jest.fn(async () => 'bcrt1fixed')
      });

      await expect(
        displayAddress({
          descriptor: `wpkh(${ledgerKey})`,
          session
        })
      ).resolves.toBe('bcrt1fixed');

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
          index: 0
        })
      ).resolves.toEqual(signature);
      expect(session.client.signMessage).toHaveBeenCalledWith(
        fromUtf8('hello'),
        "m/84'/1'/0'/0/0"
      );

      const fixedKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/0/0'
      });
      await expect(
        signMessage({
          session,
          message: 'fixed',
          descriptor: `wpkh(${fixedKey})`
        })
      ).resolves.toEqual(signature);
      expect(session.client.signMessage).toHaveBeenLastCalledWith(
        fromUtf8('fixed'),
        "m/84'/1'/0'/0/0"
      );
    });

    test('reads Ledger app metadata from a Uint8Array transport response', async () => {
      await expect(
        assertLedgerApp({
          transport: ledgerAppTransport({ version: '2.4.0' }),
          name: 'Bitcoin',
          minVersion: '2.1.0'
        })
      ).resolves.toBeUndefined();
    });

    test('compares validated Ledger app versions', async () => {
      await expect(
        assertLedgerApp({
          transport: ledgerAppTransport({ version: '2.1.0' }),
          name: 'Bitcoin',
          minVersion: '2.1.0'
        })
      ).resolves.toBeUndefined();
      await expect(
        assertLedgerApp({
          transport: ledgerAppTransport({ version: '2.0.9' }),
          name: 'Bitcoin',
          minVersion: '2.1.0'
        })
      ).rejects.toThrow('please upgrade Bitcoin to version 2.1.0');
    });

    test.each([
      '2',
      '2.1',
      '2.1.0.1',
      '2..0',
      'foo.bar.baz',
      '01.2.3',
      '-1.2.3',
      '1e2.0.0',
      '9007199254740992.0.0'
    ])('rejects malformed minimum Ledger app version %s', async minVersion => {
      await expect(
        assertLedgerApp({
          transport: ledgerAppTransport({ version: '2.4.0' }),
          name: 'Bitcoin',
          minVersion
        })
      ).rejects.toThrow(
        'Pass a minVersion using semver notation: major.minor.patch'
      );
    });

    test.each([
      '2',
      '2.1',
      '2.1.0.1',
      '2..0',
      'foo.bar.baz',
      '01.2.3',
      '-1.2.3',
      '1e2.0.0',
      '9007199254740992.0.0'
    ])('rejects malformed Ledger app version %s', async version => {
      await expect(
        assertLedgerApp({
          transport: ledgerAppTransport({ version }),
          name: 'Bitcoin',
          minVersion: '2.1.0'
        })
      ).rejects.toThrow(`Ledger returned an invalid app version: ${version}`);
    });

    test('checks the open Ledger app before validating versions', async () => {
      await expect(
        assertLedgerApp({
          transport: ledgerAppTransport({
            name: 'Ethereum',
            version: 'invalid'
          }),
          name: 'Bitcoin',
          minVersion: 'invalid'
        })
      ).rejects.toThrow('Open the Bitcoin app and try again');
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
          index: 0
        })
      ).rejects.toThrow(
        'standard single-key pkh, sh(wpkh), and wpkh descriptors'
      );
      expect(session.client.signMessage).not.toHaveBeenCalled();
    });

    test('validates address position params before device calls', async () => {
      const ledgerMaster = makeMaster(275);
      const rangedKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/0/*'
      });
      const fixedKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/0/3'
      });
      const multipathKey = keyExpressionBIP32({
        masterNode: ledgerMaster,
        originPath: "/84'/1'/0'",
        keyPath: '/<0;1>/*'
      });
      const session = mockLedgerSession(ledgerMaster.fingerprint);

      await expect(
        displayAddress({ descriptor: `wpkh(${rangedKey})`, session })
      ).rejects.toThrow('index was not provided for ranged descriptor');
      await expect(
        displayAddress({ descriptor: `wpkh(${fixedKey})`, session, index: 3 })
      ).rejects.toThrow('index passed for non-ranged descriptor');
      await expect(
        displayAddress({
          descriptor: `wpkh(${rangedKey})`,
          session,
          change: 0,
          index: 3
        })
      ).rejects.toThrow('change passed for descriptor without multipath');
      await expect(
        displayAddress({
          descriptor: `wpkh(${multipathKey})`,
          session,
          index: 3
        })
      ).rejects.toThrow('change was not provided for multipath descriptor');
    });

    test('opens selected React Native HID devices', async () => {
      const transport = mockLedgerTransport();
      mockHidOpen.mockResolvedValueOnce(transport);
      const store = {};
      const device = { vendorId: 11415, productId: 1 };

      const session = await connect({
        driver: {
          transport: {
            default: { create: jest.fn(), open: mockHidOpen }
          },
          bitcoinApi: BITCOIN_API,
          device
        },
        network: NETWORK,
        store
      });

      expect(mockHidOpen).toHaveBeenCalledWith(device);
      expect(session.network).toBe(NETWORK);
      expect(session.store).toEqual({ masterFingerprint: 'aabbccdd' });
      const closing = session.close();
      expect(session.close()).toBe(closing);
      await closing;
      expect(transport.close).toHaveBeenCalledTimes(1);
    });

    test('opens selected React Native BLE devices', async () => {
      const transport = mockLedgerTransport();
      mockBleOpen.mockResolvedValueOnce(transport);
      const store = {};

      const session = await connect({
        driver: {
          transport: Promise.resolve({
            default: { create: jest.fn(), open: mockBleOpen }
          }),
          bitcoinApi: BITCOIN_API,
          device: 'ledger-ble-device-id',
          openTimeout: 10_000
        },
        network: NETWORK,
        store
      });

      expect(mockBleOpen).toHaveBeenCalledWith('ledger-ble-device-id', 10_000);
      expect(session.network).toBe(NETWORK);
      expect(session.store).toBe(store);
      await session.close();
    });

    test('closes an automatically opened Ledger when its fingerprint does not match', async () => {
      const transport = mockLedgerTransport();
      transport.close.mockRejectedValue(new Error('Ledger cleanup failed'));
      const create = jest.fn(async () => transport);

      await expect(
        connect({
          driver: {
            transport: {
              default: { create, open: jest.fn() }
            },
            bitcoinApi: BITCOIN_API
          },
          network: NETWORK,
          store: { masterFingerprint: 'deadbeef' }
        })
      ).rejects.toThrow(
        'Connected Ledger fingerprint aabbccdd does not match store fingerprint deadbeef'
      );

      expect(create).toHaveBeenCalledWith();
      expect(transport.close).toHaveBeenCalledTimes(1);
    });

    test('reuses a rejected Ledger session close promise', async () => {
      const transport = mockLedgerTransport();
      transport.close.mockRejectedValue(new Error('Ledger close failed'));
      mockHidOpen.mockResolvedValueOnce(transport);
      const session = await connect({
        driver: {
          transport: {
            default: { create: jest.fn(), open: mockHidOpen }
          },
          bitcoinApi: BITCOIN_API,
          device: { vendorId: 11415, productId: 1 }
        },
        network: NETWORK,
        store: {}
      });

      const closing = session.close();
      expect(session.close()).toBe(closing);
      await expect(closing).rejects.toThrow('Ledger close failed');
      expect(transport.close).toHaveBeenCalledTimes(1);
    });
  }
);
