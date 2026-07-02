// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks, Transaction } from 'bitcoinjs-lib';
import type { BIP32InterfaceLike } from '../dist/bitcoinLib';
import { DescriptorsFactory } from '../dist/descriptors';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import { keyExpressionBIP32 } from '../dist/keyExpressions';
import { createPsbt } from './helpers/psbt';
import {
  bitboxKeypathFromString,
  connectors,
  displayAddress,
  keyExpression,
  registerWallet,
  scriptExpressions,
  signers,
  type BitBoxClient,
  type Manager,
  type BitBoxRegisterXPubType,
  type BitBoxScriptConfig
} from '../dist/bitbox';

const NETWORK = networks.regtest;
const { Output, BIP32 } = DescriptorsFactory(createBitcoinjsLib(ecc));
const HARDENED = 0x80000000;
const SHA256_DIGEST =
  '6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333';

type FakeBitBoxClient = BitBoxClient & {
  registered:
    | {
        apiNetwork: string;
        scriptConfig: BitBoxScriptConfig;
        keypathAccount: number[] | undefined;
        xpubType: BitBoxRegisterXPubType;
        name: string | undefined;
      }
    | undefined;
  displayed:
    | {
        apiNetwork: string;
        keypath: number[];
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
};

function makeMaster(seed: number): BIP32InterfaceLike {
  return BIP32.fromSeed(new Uint8Array(32).fill(seed), NETWORK);
}

function managerFor(master: BIP32InterfaceLike, client: BitBoxClient) {
  return connectors.fromClient({
    client,
    state: { masterFingerprint: master.fingerprint },
    Output,
    network: NETWORK
  }) satisfies Manager;
}

function fakeClientFor(master: BIP32InterfaceLike) {
  const client = {
    registered: undefined as
      | {
          apiNetwork: string;
          scriptConfig: BitBoxScriptConfig;
          keypathAccount: number[] | undefined;
          xpubType: BitBoxRegisterXPubType;
          name: string | undefined;
        }
      | undefined,
    displayed: undefined as
      | {
          apiNetwork: string;
          keypath: number[];
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
    version: () => '9.99.0-test',
    rootFingerprint: () => Buffer.from(master.fingerprint).toString('hex'),
    btcXpub: async (
      _apiNetwork: string,
      keypath: string | number[],
      _xpubType: string,
      _display: boolean
    ) => {
      if (typeof keypath === 'string')
        throw new Error('unexpected string path');
      const path = keypath
        .map(index => (index >= HARDENED ? `${index - HARDENED}'` : `${index}`))
        .join('/');
      return master.derivePath(path).neutered().toBase58();
    },
    btcIsScriptConfigRegistered: async () => false,
    btcRegisterScriptConfig: async (
      apiNetwork: string,
      scriptConfig: BitBoxScriptConfig,
      keypathAccount: string | number[] | undefined,
      xpubType: BitBoxRegisterXPubType,
      name?: string
    ) => {
      if (typeof keypathAccount === 'string')
        throw new Error('unexpected string path');
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
      if (typeof keypath === 'string')
        throw new Error('unexpected string path');
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
      return `${psbt}:signed`;
    }
  } satisfies FakeBitBoxClient;

  return client;
}

describe('BitBox helpers', () => {
  test('parses BitBox keypaths', () => {
    expect(bitboxKeypathFromString("m/48'/1'/0'/2'/0/7")).toEqual([
      48 + HARDENED,
      1 + HARDENED,
      HARDENED,
      2 + HARDENED,
      0,
      7
    ]);
  });

  test('builds key expressions and registers P2WSH multisig accounts', async () => {
    const bitboxMaster = makeMaster(1);
    const otherMaster = makeMaster(2);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);
    const originPath = "/48'/1'/0'/2'";

    const bitboxKey = await keyExpression({
      manager: bitboxManager,
      originPath,
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath,
      keyPath: '/0/*'
    });
    const descriptor = `wsh(sortedmulti(1,${bitboxKey},${otherKey}))`;

    await registerWallet({
      descriptor,
      manager: bitboxManager,
      policyName: 'Test BitBox'
    });

    expect(client.registered?.name).toBe('Test BitBox');
    expect(client.registered?.apiNetwork).toBe('tbtc');
    expect(client.registered?.keypathAccount).toEqual([
      48 + HARDENED,
      1 + HARDENED,
      HARDENED,
      2 + HARDENED
    ]);
    expect(client.registered?.scriptConfig).toMatchObject({
      multisig: { threshold: 1, ourXpubIndex: 0, scriptType: 'p2wsh' }
    });
    expect(
      client.registered &&
        'multisig' in client.registered.scriptConfig &&
        client.registered.scriptConfig.multisig.xpubs.length
    ).toBe(2);

    await expect(
      displayAddress({
        descriptor,
        manager: bitboxManager,
        change: 0,
        index: 7
      })
    ).resolves.toBe('bcrt1multisig');
    expect(client.displayed?.keypath).toEqual([
      48 + HARDENED,
      1 + HARDENED,
      HARDENED,
      2 + HARDENED,
      0,
      7
    ]);
  });

  test('displays standard single-sig addresses', async () => {
    const bitboxMaster = makeMaster(3);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);
    const descriptor = await scriptExpressions.wpkh({
      manager: bitboxManager,
      account: 0,
      change: 0,
      index: '*'
    });

    await expect(
      displayAddress({ descriptor, manager: bitboxManager, index: 7 })
    ).resolves.toBe('bcrt1simple');

    expect(client.displayed).toEqual({
      apiNetwork: 'tbtc',
      keypath: [84 + HARDENED, 1 + HARDENED, HARDENED, 0, 7],
      scriptConfig: { simpleType: 'p2wpkh' },
      display: true
    });
  });

  test('rejects top-level legacy pkh descriptors before calling the device', async () => {
    const bitboxMaster = makeMaster(8);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);

    await expect(
      scriptExpressions.pkh({
        manager: bitboxManager,
        account: 0,
        change: 0,
        index: '*'
      })
    ).rejects.toThrow('top-level legacy p2pkh');

    const bitboxKey = await keyExpression({
      manager: bitboxManager,
      originPath: "/44'/1'/0'",
      keyPath: '/0/*'
    });
    await expect(
      registerWallet({
        descriptor: `pkh(${bitboxKey})`,
        manager: bitboxManager,
        policyName: 'Test pkh'
      })
    ).rejects.toThrow('top-level legacy p2pkh');
    expect(client.registered).toBeUndefined();
    expect(client.displayed).toBeUndefined();
    expect(client.signed).toBeUndefined();
  });

  test('does not reject Miniscript pkh fragments as legacy addresses', async () => {
    const bitboxMaster = makeMaster(9);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      manager: bitboxManager,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    const descriptor = `wsh(pkh(${bitboxKey}))`;

    await registerWallet({
      descriptor,
      manager: bitboxManager,
      policyName: 'Test Miniscript pkh'
    });

    expect(client.registered?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(pkh(@0/**))' }
    });
  });

  test('registers and displays P2WSH Miniscript policies', async () => {
    const bitboxMaster = makeMaster(5);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);
    const originPath = "/48'/1'/1'/2'";
    const bitboxKey = await keyExpression({
      manager: bitboxManager,
      originPath,
      keyPath: '/0/*'
    });
    const descriptor = `wsh(and_v(v:pk(${bitboxKey}),older(5)))`;

    await registerWallet({
      descriptor,
      manager: bitboxManager,
      policyName: 'Test Policy'
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
      displayAddress({ descriptor, manager: bitboxManager, index: 9 })
    ).resolves.toBe('bcrt1policy');
    expect(client.displayed?.keypath).toEqual([
      48 + HARDENED,
      1 + HARDENED,
      1 + HARDENED,
      2 + HARDENED,
      0,
      9
    ]);
    expect(client.displayed?.scriptConfig).toMatchObject({
      policy: { policy: 'wsh(and_v(v:pk(@0/**),older(5)))' }
    });
  });

  test('signs PSBTs through bitbox-api btcSignPSBT', async () => {
    const bitboxMaster = makeMaster(4);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);
    const signedPsbt = { signed: true };
    const psbtConstructor = {
      fromBuffer: jest.fn(() => signedPsbt),
      fromBase64(
        this: { fromBuffer(psbtBase64: string): unknown },
        psbtBase64: string
      ) {
        return this.fromBuffer(psbtBase64);
      }
    };
    const psbt = {
      addInput: jest.fn(),
      addOutput: jest.fn(),
      inputCount: 0,
      data: { inputs: [] },
      txInputs: [],
      locktime: 0,
      setLocktime: jest.fn(),
      signInput: jest.fn(),
      signAllInputs: jest.fn(),
      signInputHD: jest.fn(),
      signAllInputsHD: jest.fn(),
      finalizeInput: jest.fn(),
      finalizeTaprootInput: jest.fn(),
      validateSignaturesOfInput: jest.fn(),
      updateInput: jest.fn(),
      combine: jest.fn(),
      constructor: psbtConstructor,
      toBase64: () => 'cHNidP8BAA='
    };

    await expect(signers.sign({ psbt, manager: bitboxManager })).resolves.toBe(
      'cHNidP8BAA=:signed'
    );
    expect(client.signed).toEqual({
      apiNetwork: 'tbtc',
      psbt: 'cHNidP8BAA=',
      forceScriptConfig: undefined,
      formatUnit: 'default'
    });
    expect(psbtConstructor.fromBuffer).toHaveBeenCalledWith(
      'cHNidP8BAA=:signed'
    );
    expect(psbt.combine).toHaveBeenCalledWith(signedPsbt);
  });

  test('rejects sha256 Miniscript policy derivation before calling the device', async () => {
    const bitboxMaster = makeMaster(7);
    const client = fakeClientFor(bitboxMaster);
    const bitboxManager = managerFor(bitboxMaster, client);
    const bitboxKey = await keyExpression({
      manager: bitboxManager,
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
    await registerWallet({
      descriptor,
      manager: bitboxManager,
      policyName: 'Test sha256'
    });
    await expect(
      displayAddress({ descriptor, manager: bitboxManager, index: 0 })
    ).rejects.toThrow('sha256/hash256/hash160/ripemd160');
    expect(client.displayed).toBeUndefined();
    const fundingTx = new Transaction();
    fundingTx.version = 2;
    fundingTx.addInput(Buffer.alloc(32, 7), 0xffffffff);
    fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), BigInt(20_000));
    const psbt = createPsbt(false, NETWORK);
    output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });

    await expect(
      signers.sign({ psbt, manager: bitboxManager })
    ).rejects.toThrow('sha256/hash256/hash160/ripemd160');
    expect(client.signed).toBeUndefined();
  });
});
