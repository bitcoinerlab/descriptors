// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks, Psbt, Transaction } from 'bitcoinjs-lib';
import { fromUtf8, toHex } from 'uint8array-tools';
import type { BIP32InterfaceLike } from '../dist/bitcoinLib';
import { DescriptorsFactory } from '../dist/descriptors';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import { keyExpressionBIP32 } from '../dist/keyExpressions';
import { createPsbt } from './helpers/psbt';
import {
  connect,
  displayAddress,
  keyExpression,
  registerPolicy,
  scriptExpressions,
  signMessage,
  signers,
  type Session
} from '../dist/bitbox';

const NETWORK = networks.regtest;
const { Output, BIP32 } = DescriptorsFactory(createBitcoinjsLib(ecc));
const SHA256_DIGEST =
  '6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333';
const MESSAGE_SIGNATURE = new Uint8Array(65).fill(2);

type ProviderClient = Session['client'];
type BitBoxScriptConfig = Parameters<ProviderClient['btcAddress']>[2];

type FakeBitBoxClient = ProviderClient & {
  close(): Promise<void>;
  xpubRequests: {
    apiNetwork: string;
    keypath: string;
    xpubType: string;
    display: boolean;
  }[];
  registered:
    | {
        apiNetwork: string;
        scriptConfig: BitBoxScriptConfig;
        keypathAccount: string | undefined;
        xpubType: string;
        name: string | undefined;
      }
    | undefined;
  displayed:
    | {
        apiNetwork: string;
        keypath: string;
        scriptConfig: BitBoxScriptConfig;
        display: boolean;
      }
    | undefined;
  signed:
    | {
        apiNetwork: string;
        psbt: string;
        forceScriptConfig: unknown;
        formatUnit: string;
      }
    | undefined;
  messageSigned:
    | {
        apiNetwork: string;
        scriptConfig: BitBoxScriptConfig;
        keypath: string;
        message: Uint8Array;
      }
    | undefined;
};

function makeMaster(seed: number, network = NETWORK): BIP32InterfaceLike {
  return BIP32.fromSeed(new Uint8Array(32).fill(seed), network);
}

function sessionFor(
  master: BIP32InterfaceLike,
  client: ProviderClient,
  network = NETWORK
): Session {
  return {
    client,
    store: { masterFingerprint: toHex(master.fingerprint) },
    network,
    close: () => Promise.resolve()
  } satisfies Session;
}

function fakeClientFor(master: BIP32InterfaceLike) {
  const client = {
    xpubRequests: [] as {
      apiNetwork: string;
      keypath: string;
      xpubType: string;
      display: boolean;
    }[],
    registered: undefined as
      | {
          apiNetwork: string;
          scriptConfig: BitBoxScriptConfig;
          keypathAccount: string | undefined;
          xpubType: string;
          name: string | undefined;
        }
      | undefined,
    displayed: undefined as
      | {
          apiNetwork: string;
          keypath: string;
          scriptConfig: BitBoxScriptConfig;
          display: boolean;
        }
      | undefined,
    signed: undefined as
      | {
          apiNetwork: string;
          psbt: string;
          forceScriptConfig: unknown;
          formatUnit: string;
        }
      | undefined,
    messageSigned: undefined as
      | {
          apiNetwork: string;
          scriptConfig: BitBoxScriptConfig;
          keypath: string;
          message: Uint8Array;
        }
      | undefined,
    close: jest.fn(async () => undefined),
    version: () => '9.99.0-test',
    rootFingerprint: () => Buffer.from(master.fingerprint).toString('hex'),
    btcXpub: async (
      apiNetwork: string,
      keypath: string | number[],
      xpubType: string,
      display: boolean
    ) => {
      if (typeof keypath !== 'string')
        throw new Error('unexpected number path');
      client.xpubRequests.push({ apiNetwork, keypath, xpubType, display });
      return master
        .derivePath(keypath.startsWith('m/') ? keypath.slice(2) : keypath)
        .neutered()
        .toBase58();
    },
    btcIsScriptConfigRegistered: async (): Promise<boolean> => false,
    btcRegisterScriptConfig: async (
      apiNetwork: string,
      scriptConfig: BitBoxScriptConfig,
      keypathAccount: string | number[] | undefined,
      xpubType: string,
      name?: string
    ) => {
      if (keypathAccount !== undefined && typeof keypathAccount !== 'string')
        throw new Error('unexpected number path');
      client.registered = {
        apiNetwork,
        scriptConfig,
        keypathAccount,
        xpubType,
        name
      };
    },
    btcAddress: async (
      apiNetwork: string,
      keypath: string | number[],
      scriptConfig: BitBoxScriptConfig,
      display: boolean
    ) => {
      if (typeof keypath !== 'string')
        throw new Error('unexpected number path');
      client.displayed = { apiNetwork, keypath, scriptConfig, display };
      return 'multisig' in scriptConfig
        ? 'bcrt1multisig'
        : 'policy' in scriptConfig
          ? 'bcrt1policy'
          : 'bcrt1simple';
    },
    btcSignPSBT: async (
      apiNetwork: string,
      psbt: string,
      forceScriptConfig: unknown,
      formatUnit: string
    ) => {
      client.signed = { apiNetwork, psbt, forceScriptConfig, formatUnit };
      return psbt;
    },
    btcSignMessage: async (
      apiNetwork: string,
      {
        scriptConfig,
        keypath
      }: { scriptConfig: BitBoxScriptConfig; keypath: string | number[] },
      message: Uint8Array
    ) => {
      if (typeof keypath !== 'string')
        throw new Error('unexpected number path');
      client.messageSigned = { apiNetwork, scriptConfig, keypath, message };
      return {
        sig: new Uint8Array([1]),
        recid: 0n,
        electrumSig65: new Uint8Array(MESSAGE_SIGNATURE)
      };
    }
  } satisfies FakeBitBoxClient;

  return client;
}

function addDescriptorInput({
  psbt,
  descriptor,
  index,
  seed
}: {
  psbt: Psbt;
  descriptor: string;
  index: number;
  seed: number;
}) {
  const output = new Output({ descriptor, index, network: NETWORK });
  const fundingTx = new Transaction();
  fundingTx.addInput(Buffer.alloc(32, seed), 0xffffffff);
  fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), 20_000n);
  output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });
}

describe('BitBox helpers', () => {
  test('connects through an injected single-mode driver', async () => {
    const bitboxMaster = makeMaster(15);
    const client = fakeClientFor(bitboxMaster);
    const store = {};
    const connectBitBoxNovaBle = jest.fn(async () => client);

    const session = await connect({
      driver: {
        module: Promise.resolve({ connectBitBoxNovaBle }),
        device: { deviceId: 'ble-device' },
        timeoutMs: 60_000,
        formatUnit: 'sat'
      },
      network: NETWORK,
      store
    });

    expect(connectBitBoxNovaBle).toHaveBeenCalledWith({
      timeoutMs: 60_000,
      deviceId: 'ble-device'
    });
    expect(session.store).toEqual({
      masterFingerprint: toHex(bitboxMaster.fingerprint)
    });
    expect(session.formatUnit).toBe('sat');
    const closing = session.close();
    expect(session.close()).toBe(closing);
    await closing;
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  test('requires a mode when a BitBox driver exposes several', async () => {
    const bitboxMaster = makeMaster(16);
    const client = fakeClientFor(bitboxMaster);

    await expect(
      connect({
        driver: {
          module: {
            connectBitBoxNovaBle: async () => client,
            connectBitBoxUsb: async () => client
          }
        },
        network: NETWORK,
        store: {}
      })
    ).rejects.toThrow(
      'BitBox driver supports multiple modes: "ble", "usb". Pass driver.mode.'
    );
  });

  test('closes a BitBox when its fingerprint does not match the store', async () => {
    const bitboxMaster = makeMaster(18);
    const client = fakeClientFor(bitboxMaster);
    client.close.mockRejectedValue(new Error('BitBox cleanup failed'));

    await expect(
      connect({
        driver: {
          module: {
            connectBitBoxUsb: async () => client
          }
        },
        network: NETWORK,
        store: { masterFingerprint: 'deadbeef' }
      })
    ).rejects.toThrow(
      `Connected BitBox fingerprint ${toHex(bitboxMaster.fingerprint)} does not match store fingerprint deadbeef`
    );

    expect(client.close).toHaveBeenCalledTimes(1);
  });

  test('reuses a rejected BitBox session close promise', async () => {
    const bitboxMaster = makeMaster(22);
    const client = fakeClientFor(bitboxMaster);
    client.close.mockRejectedValue(new Error('BitBox close failed'));
    const session = await connect({
      driver: { module: { connectBitBoxUsb: async () => client } },
      network: NETWORK,
      store: {}
    });

    const closing = session.close();
    expect(session.close()).toBe(closing);
    await expect(closing).rejects.toThrow('BitBox close failed');
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  test('preserves unlock errors when freeing a BitBox connection fails', async () => {
    const free = jest.fn(() => {
      throw new Error('BitBox connection cleanup failed');
    });

    await expect(
      connect({
        driver: {
          module: {
            bitbox02ConnectBridge: async () => ({
              free,
              unlockAndPair: async () => {
                throw new Error('BitBox unlock failed');
              }
            })
          },
          onPairingCode: jest.fn()
        },
        network: NETWORK,
        store: {}
      })
    ).rejects.toThrow('BitBox unlock failed');
    expect(free).toHaveBeenCalledTimes(1);
  });

  test('preserves confirmation errors when freeing BitBox pairing fails', async () => {
    const free = jest.fn(() => {
      throw new Error('BitBox pairing cleanup failed');
    });

    await expect(
      connect({
        driver: {
          module: {
            bitbox02ConnectBridge: async () => ({
              unlockAndPair: async () => ({
                free,
                getPairingCode: () => undefined,
                waitConfirm: async () => {
                  throw new Error('BitBox confirmation failed');
                }
              })
            })
          },
          onPairingCode: jest.fn()
        },
        network: NETWORK,
        store: {}
      })
    ).rejects.toThrow('BitBox confirmation failed');
    expect(free).toHaveBeenCalledTimes(1);
  });

  test('shows bitbox-api pairing codes before confirmation', async () => {
    const bitboxMaster = makeMaster(17);
    const client = fakeClientFor(bitboxMaster);
    const onPairingCode = jest.fn(async () => undefined);
    const waitConfirm = jest.fn(async () => client);

    const session = await connect({
      driver: {
        module: {
          bitbox02ConnectBridge: async () => ({
            unlockAndPair: async () => ({
              getPairingCode: () => '123 456',
              waitConfirm
            })
          })
        },
        onPairingCode
      },
      network: NETWORK,
      store: {}
    });

    expect(onPairingCode).toHaveBeenCalledWith('123 456');
    expect(waitConfirm).toHaveBeenCalledTimes(1);
    await session.close();
  });

  test('builds key expressions and registers P2WSH multisig natively', async () => {
    const bitboxMaster = makeMaster(1);
    const otherMaster = makeMaster(2);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const originPath = "/48'/1'/0'/2'";

    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath,
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath,
      keyPath: '/0/*'
    });
    const descriptor = `wsh(sortedmulti(1,${bitboxKey},${otherKey}))`;

    await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Test BitBox'
    });

    expect(client.registered?.name).toBe('Test BitBox');
    expect(client.registered?.apiNetwork).toBe('tbtc');
    expect(client.registered?.keypathAccount).toBe("m/48'/1'/0'/2'");
    expect(client.registered?.scriptConfig).toMatchObject({
      multisig: { threshold: 1, ourXpubIndex: 0, scriptType: 'p2wsh' }
    });
    expect(
      client.registered &&
        'multisig' in client.registered.scriptConfig &&
        client.registered.scriptConfig.multisig.xpubs.length
    ).toBe(2);
    expect(bitboxSession.store.policies?.[0]).toEqual({
      name: 'Test BitBox',
      descriptorTemplate: 'wsh(sortedmulti(1,@0/**,@1/**))',
      keyRoots: expect.any(Array)
    });

    await expect(
      displayAddress({
        descriptor,
        session: bitboxSession,
        index: 7
      })
    ).resolves.toBe('bcrt1multisig');
    expect(client.displayed?.keypath).toBe("m/48'/1'/0'/2'/0/7");
    expect(client.displayed?.scriptConfig).toMatchObject({
      multisig: { threshold: 1, ourXpubIndex: 0, scriptType: 'p2wsh' }
    });

    const output = new Output({ descriptor, index: 0, network: NETWORK });
    const fundingTx = new Transaction();
    fundingTx.version = 2;
    fundingTx.addInput(Buffer.alloc(32, 1), 0xffffffff);
    fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), BigInt(20_000));
    const psbt = createPsbt(false, NETWORK);
    output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });

    await signers.sign({ psbt, session: bitboxSession });
    expect(client.signed?.forceScriptConfig).toMatchObject({
      scriptConfig: {
        multisig: { threshold: 1, ourXpubIndex: 0, scriptType: 'p2wsh' }
      },
      keypath: "m/48'/1'/0'/2'"
    });
  });

  test('passes xpub and registration modes to BitBox-compatible clients', async () => {
    const testnetMaster = makeMaster(10, NETWORK);
    const testnetClient = fakeClientFor(testnetMaster);
    const testnetSession = sessionFor(testnetMaster, testnetClient, NETWORK);

    await keyExpression({
      session: testnetSession,
      originPath: "/84'/1'/0'",
      keyPath: '/0/*'
    });

    expect(testnetClient.xpubRequests[0]).toMatchObject({
      apiNetwork: 'tbtc',
      keypath: "m/84'/1'/0'",
      xpubType: 'tpub',
      display: false
    });

    const testnetKey = await keyExpression({
      session: testnetSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });

    expect(testnetClient.xpubRequests[1]).toMatchObject({
      apiNetwork: 'tbtc',
      keypath: "m/48'/1'/0'/2'",
      xpubType: 'tpub',
      display: false
    });

    await registerPolicy({
      descriptor: `wsh(and_v(v:pk(${testnetKey}),older(5)))`,
      session: testnetSession,
      name: 'Test provider client'
    });

    expect(testnetClient.registered?.xpubType).toBe('autoXpubTpub');

    const mainnetMaster = makeMaster(11, networks.bitcoin);
    const mainnetClient = fakeClientFor(mainnetMaster);
    const mainnetSession = sessionFor(
      mainnetMaster,
      mainnetClient,
      networks.bitcoin
    );

    await keyExpression({
      session: mainnetSession,
      originPath: "/84'/0'/0'",
      keyPath: '/0/*'
    });

    expect(mainnetClient.xpubRequests[0]).toMatchObject({
      apiNetwork: 'btc',
      keypath: "m/84'/0'/0'",
      xpubType: 'xpub',
      display: false
    });
  });

  test('rechecks cached policies and restores missing device registration', async () => {
    const bitboxMaster = makeMaster(21);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    const descriptor = `wsh(and_v(v:pk(${bitboxKey}),older(5)))`;
    const isRegistered = jest.spyOn(client, 'btcIsScriptConfigRegistered');
    const register = jest.spyOn(client, 'btcRegisterScriptConfig');

    const initialRegistration = await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Cached policy'
    });
    expect(initialRegistration).toBe(false);
    expect(bitboxSession.store.policies).toHaveLength(1);

    isRegistered.mockResolvedValue(true);
    isRegistered.mockClear();
    register.mockClear();
    const cachedRegistration = await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Cached policy'
    });
    expect(cachedRegistration).toBe(true);
    expect(isRegistered).toHaveBeenCalledTimes(1);
    expect(register).not.toHaveBeenCalled();
    expect(bitboxSession.store.policies).toHaveLength(1);

    isRegistered.mockResolvedValue(false);
    isRegistered.mockClear();
    const restoredRegistration = await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Cached policy'
    });
    expect(restoredRegistration).toBe(false);
    expect(isRegistered).toHaveBeenCalledTimes(1);
    expect(register).toHaveBeenCalledTimes(1);
    expect(bitboxSession.store.policies).toHaveLength(1);

    isRegistered.mockReset();
    isRegistered.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    register.mockClear();
    register.mockRejectedValueOnce({ code: 'bitbox-duplicate' });
    const racedRegistration = await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Cached policy'
    });
    expect(racedRegistration).toBe(false);
    expect(isRegistered).toHaveBeenCalledTimes(2);
    expect(register).toHaveBeenCalledTimes(1);
    expect(bitboxSession.store).not.toHaveProperty('wasPolicyStoredOnDevice');

    isRegistered.mockClear();
    await expect(
      registerPolicy({
        descriptor,
        session: bitboxSession,
        name: 'Renamed policy'
      })
    ).rejects.toThrow(
      'policy was already registered with a different name: Cached policy'
    );
    expect(isRegistered).not.toHaveBeenCalled();
  });

  test('displays standard single-sig addresses', async () => {
    const bitboxMaster = makeMaster(3);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const descriptor = await scriptExpressions.wpkh({
      session: bitboxSession,
      account: 0,
      change: 0,
      index: '*'
    });
    const isRegistered = jest.spyOn(client, 'btcIsScriptConfigRegistered');
    const register = jest.spyOn(client, 'btcRegisterScriptConfig');

    const registration = await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Standard policy'
    });
    expect(registration).toBeUndefined();
    expect(isRegistered).not.toHaveBeenCalled();
    expect(register).not.toHaveBeenCalled();

    await expect(
      displayAddress({ descriptor, session: bitboxSession, index: 7 })
    ).resolves.toBe('bcrt1simple');

    expect(client.displayed).toEqual({
      apiNetwork: 'tbtc',
      keypath: "m/84'/1'/0'/0/7",
      scriptConfig: { simpleType: 'p2wpkh' },
      display: true
    });

    const fixedKey = await keyExpression({
      session: bitboxSession,
      originPath: "/84'/1'/0'",
      keyPath: '/0/3'
    });
    await expect(
      displayAddress({
        descriptor: `wpkh(${fixedKey})`,
        session: bitboxSession
      })
    ).resolves.toBe('bcrt1simple');
    expect(client.displayed).toEqual({
      apiNetwork: 'tbtc',
      keypath: "m/84'/1'/0'/0/3",
      scriptConfig: { simpleType: 'p2wpkh' },
      display: true
    });
  });

  test('validates address position params before BitBox calls', async () => {
    const bitboxMaster = makeMaster(14);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const rangedKey = await keyExpression({
      session: bitboxSession,
      originPath: "/84'/1'/0'",
      keyPath: '/0/*'
    });
    const fixedKey = await keyExpression({
      session: bitboxSession,
      originPath: "/84'/1'/0'",
      keyPath: '/0/3'
    });
    const multipathKey = await keyExpression({
      session: bitboxSession,
      originPath: "/84'/1'/0'",
      keyPath: '/<0;1>/*'
    });

    await expect(
      displayAddress({
        descriptor: `wpkh(${rangedKey})`,
        session: bitboxSession
      })
    ).rejects.toThrow('index was not provided for ranged descriptor');
    await expect(
      displayAddress({
        descriptor: `wpkh(${fixedKey})`,
        session: bitboxSession,
        index: 3
      })
    ).rejects.toThrow('index passed for non-ranged descriptor');
    await expect(
      displayAddress({
        descriptor: `wpkh(${rangedKey})`,
        session: bitboxSession,
        change: 0,
        index: 3
      })
    ).rejects.toThrow('change passed for descriptor without multipath');
    await expect(
      displayAddress({
        descriptor: `wpkh(${multipathKey})`,
        session: bitboxSession,
        index: 3
      })
    ).rejects.toThrow('change was not provided for multipath descriptor');
    expect(client.displayed).toBeUndefined();
  });

  test('rejects top-level legacy pkh descriptors before calling the device', async () => {
    const bitboxMaster = makeMaster(8);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);

    await expect(
      scriptExpressions.pkh({
        session: bitboxSession,
        account: 0,
        change: 0,
        index: '*'
      })
    ).rejects.toThrow('top-level legacy p2pkh');

    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath: "/44'/1'/0'",
      keyPath: '/0/*'
    });
    await expect(
      registerPolicy({
        descriptor: `pkh(${bitboxKey})`,
        session: bitboxSession,
        name: 'Test pkh'
      })
    ).rejects.toThrow('top-level legacy p2pkh');
    expect(client.registered).toBeUndefined();
    expect(client.displayed).toBeUndefined();
    expect(client.signed).toBeUndefined();
  });

  test('does not reject Miniscript pkh fragments as legacy addresses', async () => {
    const bitboxMaster = makeMaster(9);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    const descriptor = `wsh(pkh(${bitboxKey}))`;

    await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Test Miniscript pkh'
    });

    expect(client.registered?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(pkh(@0/**))' }
    });
  });

  test('keeps ordered P2WSH multi policies generic', async () => {
    const bitboxMaster = makeMaster(12);
    const otherMaster = makeMaster(13);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/3'",
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath: "/48'/1'/0'/3'",
      keyPath: '/0/*'
    });
    const descriptor = `wsh(multi(1,${bitboxKey},${otherKey}))`;

    await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Ordered Multi'
    });

    expect(client.registered?.keypathAccount).toBeUndefined();
    expect(client.registered?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(multi(1,@0/**,@1/**))' }
    });

    await expect(
      displayAddress({ descriptor, session: bitboxSession, index: 3 })
    ).resolves.toBe('bcrt1policy');
    expect(client.displayed?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(multi(1,@0/**,@1/**))' }
    });
  });

  test('registers and displays P2WSH Miniscript policies', async () => {
    const bitboxMaster = makeMaster(5);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const originPath = "/48'/1'/1'/2'";
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath,
      keyPath: '/0/*'
    });
    const descriptor = `wsh(and_v(v:pk(${bitboxKey}),older(5)))`;

    await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Test Policy'
    });

    expect(client.registered?.name).toBe('Test Policy');
    expect(client.registered?.keypathAccount).toBeUndefined();
    expect(client.registered?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(and_v(v:pk(@0/**),older(5)))' }
    });
    expect(
      client.registered &&
        'policy' in client.registered.scriptConfig &&
        client.registered.scriptConfig.policy.keys.length
    ).toBe(1);

    await expect(
      displayAddress({ descriptor, session: bitboxSession, index: 9 })
    ).resolves.toBe('bcrt1policy');
    expect(client.displayed?.keypath).toBe("m/48'/1'/1'/2'/0/9");
    expect(client.displayed?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(and_v(v:pk(@0/**),older(5)))' }
    });

    const fixedKey = await keyExpression({
      session: bitboxSession,
      originPath,
      keyPath: '/0/9'
    });
    await expect(
      displayAddress({
        descriptor: `wsh(and_v(v:pk(${fixedKey}),older(5)))`,
        session: bitboxSession
      })
    ).resolves.toBe('bcrt1policy');
    expect(client.displayed?.keypath).toBe("m/48'/1'/1'/2'/0/9");
  });

  test.each(['/**', '/<0;1>/*'])(
    'registers BitBox policies from the generalized key path %s',
    async keyPath => {
      const bitboxMaster = makeMaster(19);
      const client = fakeClientFor(bitboxMaster);
      const bitboxSession = sessionFor(bitboxMaster, client);
      const bitboxKey = await keyExpression({
        session: bitboxSession,
        originPath: "/48'/1'/0'/2'",
        keyPath
      });

      await registerPolicy({
        descriptor: `wsh(and_v(v:pk(${bitboxKey}),older(5)))`,
        session: bitboxSession,
        name: 'Generalized policy'
      });

      expect(client.registered?.scriptConfig).toMatchObject({
        policy: { policy: 'wsh(and_v(v:pk(@0/**),older(5)))' }
      });
      expect(bitboxSession.store.policies?.[0]).toMatchObject({
        name: 'Generalized policy',
        descriptorTemplate: 'wsh(and_v(v:pk(@0/**),older(5)))'
      });
    }
  );

  test('rejects non-receive/change multipath policies', async () => {
    const bitboxMaster = makeMaster(20);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/<2;3>/*'
    });

    await expect(
      registerPolicy({
        descriptor: `wsh(and_v(v:pk(${bitboxKey}),older(5)))`,
        session: bitboxSession,
        name: 'Unsupported policy'
      })
    ).rejects.toThrow(
      'hardware wallet policies support only receive/change multipath'
    );
    expect(client.registered).toBeUndefined();
  });

  test('rejects PSBTs containing inputs unrelated to the BitBox', async () => {
    const bitboxMaster = makeMaster(4);
    const otherMaster = makeMaster(25);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const descriptor = await scriptExpressions.wpkh({
      session: bitboxSession,
      account: 0,
      change: 0,
      index: '*'
    });
    const otherKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath: "/84'/1'/0'",
      keyPath: '/0/*'
    });
    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({
      psbt,
      descriptor,
      index: 0,
      seed: 1
    });
    addDescriptorInput({
      psbt,
      descriptor: `wpkh(${otherKey})`,
      index: 0,
      seed: 2
    });

    await expect(
      signers.sign({ psbt, session: bitboxSession })
    ).rejects.toThrow(
      'BitBox cannot sign input 1: every PSBT input must include a key owned by the connected BitBox'
    );
    expect(client.signed).toBeUndefined();
  });

  test('uses one forced config for standard and repeated policy inputs', async () => {
    const bitboxMaster = makeMaster(26);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const standardDescriptor = await scriptExpressions.wpkh({
      session: bitboxSession,
      account: 0,
      change: 0,
      index: '*'
    });
    const policyKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    const policyDescriptor = `wsh(and_v(v:pk(${policyKey}),older(5)))`;
    await registerPolicy({
      descriptor: policyDescriptor,
      session: bitboxSession,
      name: 'Repeated policy'
    });
    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({
      psbt,
      descriptor: standardDescriptor,
      index: 0,
      seed: 1
    });
    addDescriptorInput({
      psbt,
      descriptor: policyDescriptor,
      index: 0,
      seed: 2
    });
    addDescriptorInput({
      psbt,
      descriptor: policyDescriptor,
      index: 1,
      seed: 3
    });

    await signers.sign({ psbt, session: bitboxSession });

    expect(client.signed?.forceScriptConfig).toMatchObject({
      scriptConfig: {
        policy: { policy: 'wsh(and_v(v:pk(@0/**),older(5)))' }
      },
      keypath: "m/48'/1'/0'/2'"
    });
  });

  test('rejects two different generic BitBox policies before signing', async () => {
    const bitboxMaster = makeMaster(27);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const policyKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    const policyA = `wsh(and_v(v:pk(${policyKey}),older(5)))`;
    const policyB = `wsh(and_v(v:pk(${policyKey}),older(6)))`;
    await registerPolicy({
      descriptor: policyA,
      session: bitboxSession,
      name: 'Policy A'
    });
    await registerPolicy({
      descriptor: policyB,
      session: bitboxSession,
      name: 'Policy B'
    });
    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({ psbt, descriptor: policyA, index: 0, seed: 4 });
    addDescriptorInput({ psbt, descriptor: policyB, index: 0, seed: 5 });

    await expect(
      signers.sign({ psbt, session: bitboxSession })
    ).rejects.toThrow('accepts only one forced script config per PSBT');
    expect(client.signed).toBeUndefined();
  });

  test('rejects native multisig mixed with a generic BitBox policy', async () => {
    const bitboxMaster = makeMaster(28);
    const otherMaster = makeMaster(29);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const originPath = "/48'/1'/0'/2'";
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath,
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath,
      keyPath: '/0/*'
    });
    const multisigDescriptor = `wsh(sortedmulti(1,${bitboxKey},${otherKey}))`;
    const policyDescriptor = `wsh(and_v(v:pk(${bitboxKey}),older(5)))`;
    await registerPolicy({
      descriptor: multisigDescriptor,
      session: bitboxSession,
      name: 'Native multisig'
    });
    await registerPolicy({
      descriptor: policyDescriptor,
      session: bitboxSession,
      name: 'Generic policy'
    });
    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({
      psbt,
      descriptor: multisigDescriptor,
      index: 0,
      seed: 6
    });
    addDescriptorInput({
      psbt,
      descriptor: policyDescriptor,
      index: 0,
      seed: 7
    });

    await expect(
      signers.sign({ psbt, session: bitboxSession })
    ).rejects.toThrow('accepts only one forced script config per PSBT');
    expect(client.signed).toBeUndefined();
  });

  test('signs single inputs through the whole-PSBT BitBox API', async () => {
    const bitboxMaster = makeMaster(23);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const descriptor = await scriptExpressions.wpkh({
      session: bitboxSession,
      account: 0,
      change: 0,
      index: '*'
    });
    const output = new Output({ descriptor, index: 0, network: NETWORK });
    const fundingTx = new Transaction();
    fundingTx.addInput(Buffer.alloc(32, 1), 0xffffffff);
    fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), 20_000n);
    const psbt = new Psbt({ network: NETWORK });
    output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });
    const combine = jest.spyOn(psbt, 'combine');
    const psbtBase64 = psbt.toBase64();

    await expect(
      signers.signInput({ psbt, index: 0, session: bitboxSession })
    ).resolves.toBe(psbtBase64);
    expect(client.signed?.psbt).toBe(psbtBase64);
    expect(combine).toHaveBeenCalledWith(expect.any(Psbt));
  });

  test('rejects unsupported BitBox per-input signing requests', async () => {
    const bitboxMaster = makeMaster(24);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const emptyPsbt = new Psbt({ network: NETWORK });

    await expect(
      signers.signInput({ psbt: emptyPsbt, index: 0, session: bitboxSession })
    ).rejects.toThrow('input 0 not available');

    const multiInputPsbt = new Psbt({ network: NETWORK });
    multiInputPsbt.addInput({ hash: Buffer.alloc(32, 1), index: 0 });
    multiInputPsbt.addInput({ hash: Buffer.alloc(32, 2), index: 0 });
    await expect(
      signers.signInput({
        psbt: multiInputPsbt,
        index: 0,
        session: bitboxSession
      })
    ).rejects.toThrow('signInput is only supported for single-input PSBTs');
    expect(client.signed).toBeUndefined();
  });

  test('signs messages through bitbox-api btcSignMessage', async () => {
    const bitboxMaster = makeMaster(6);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const descriptor = await scriptExpressions.wpkh({
      session: bitboxSession,
      account: 0,
      change: 0,
      index: '*'
    });

    await expect(
      signMessage({
        session: bitboxSession,
        message: 'hello',
        descriptor,
        index: 0
      })
    ).resolves.toEqual(MESSAGE_SIGNATURE);
    expect(client.messageSigned).toEqual({
      apiNetwork: 'tbtc',
      scriptConfig: { simpleType: 'p2wpkh' },
      keypath: "m/84'/1'/0'/0/0",
      message: fromUtf8('hello')
    });

    const fixedKey = await keyExpression({
      session: bitboxSession,
      originPath: "/84'/1'/0'",
      keyPath: '/0/0'
    });
    await expect(
      signMessage({
        session: bitboxSession,
        message: 'fixed',
        descriptor: `wpkh(${fixedKey})`
      })
    ).resolves.toEqual(MESSAGE_SIGNATURE);
    expect(client.messageSigned).toEqual({
      apiNetwork: 'tbtc',
      scriptConfig: { simpleType: 'p2wpkh' },
      keypath: "m/84'/1'/0'/0/0",
      message: fromUtf8('fixed')
    });
  });

  test('rejects unsupported BitBox message-signing descriptors before calling the device', async () => {
    const bitboxMaster = makeMaster(12);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const pkhKey = await keyExpression({
      session: bitboxSession,
      originPath: "/44'/1'/0'",
      keyPath: '/0/*'
    });
    const trDescriptor = await scriptExpressions.tr({
      session: bitboxSession,
      account: 0,
      change: 0,
      index: '*'
    });

    await expect(
      signMessage({
        session: bitboxSession,
        message: 'hello',
        descriptor: `pkh(${pkhKey})`,
        index: 0
      })
    ).rejects.toThrow('top-level legacy p2pkh');
    await expect(
      signMessage({
        session: bitboxSession,
        message: 'hello',
        descriptor: trDescriptor,
        index: 0
      })
    ).rejects.toThrow('Taproot message signing');
    expect(client.messageSigned).toBeUndefined();
  });

  test('rejects sha256 Miniscript policy derivation before calling the device', async () => {
    const bitboxMaster = makeMaster(7);
    const client = fakeClientFor(bitboxMaster);
    const bitboxSession = sessionFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      session: bitboxSession,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    const descriptor = `wsh(and_v(v:pk(${bitboxKey}),sha256(${SHA256_DIGEST})))`;
    const output = new Output({
      descriptor,
      index: 0,
      preimages: [
        {
          digest: `sha256(${SHA256_DIGEST})`,
          preimage:
            '107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f'
        }
      ],
      network: NETWORK
    });
    await registerPolicy({
      descriptor,
      session: bitboxSession,
      name: 'Test sha256'
    });
    await expect(
      displayAddress({ descriptor, session: bitboxSession, index: 0 })
    ).rejects.toThrow('sha256/hash256/hash160/ripemd160');
    expect(client.displayed).toBeUndefined();
    const fundingTx = new Transaction();
    fundingTx.version = 2;
    fundingTx.addInput(Buffer.alloc(32, 7), 0xffffffff);
    fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), BigInt(20_000));
    const psbt = createPsbt(false, NETWORK);
    output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });

    await expect(
      signers.sign({ psbt, session: bitboxSession })
    ).rejects.toThrow('sha256/hash256/hash160/ripemd160');
    expect(client.signed).toBeUndefined();
  });
});
