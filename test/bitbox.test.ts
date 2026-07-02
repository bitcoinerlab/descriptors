// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks } from 'bitcoinjs-lib';
import type { BIP32InterfaceLike } from '../dist/bitcoinLib';
import { DescriptorsFactory } from '../dist/descriptors';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import { keyExpressionBIP32 } from '../dist/keyExpressions';
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

type FakeBitBoxClient = BitBoxClient & {
  registered:
    | {
        coin: string;
        scriptConfig: BitBoxScriptConfig;
        keypathAccount: number[] | undefined;
        xpubType: BitBoxRegisterXPubType;
        name: string | undefined;
      }
    | undefined;
  displayed:
    | {
        coin: string;
        keypath: number[];
        scriptConfig: BitBoxScriptConfig;
        display: boolean;
      }
    | undefined;
  signed:
    | {
        coin: string;
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
          coin: string;
          scriptConfig: BitBoxScriptConfig;
          keypathAccount: number[] | undefined;
          xpubType: BitBoxRegisterXPubType;
          name: string | undefined;
        }
      | undefined,
    displayed: undefined as
      | {
          coin: string;
          keypath: number[];
          scriptConfig: BitBoxScriptConfig;
          display: boolean;
        }
      | undefined,
    signed: undefined as
      | {
          coin: string;
          psbt: string;
          forceScriptConfig: unknown;
          formatUnit: string;
        }
      | undefined,
    version: () => '9.99.0-test',
    rootFingerprint: () => Buffer.from(master.fingerprint).toString('hex'),
    btcXpub: async (
      _coin: string,
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
      coin: string,
      scriptConfig: BitBoxScriptConfig,
      keypathAccount: string | number[] | undefined,
      xpubType: BitBoxRegisterXPubType,
      name?: string
    ) => {
      if (typeof keypathAccount === 'string')
        throw new Error('unexpected string path');
      client.registered = {
        coin,
        scriptConfig,
        keypathAccount,
        xpubType,
        name
      };
    },
    btcAddress: async (
      coin: string,
      keypath: string | number[],
      scriptConfig: BitBoxScriptConfig,
      display: boolean
    ) => {
      if (typeof keypath === 'string')
        throw new Error('unexpected string path');
      client.displayed = { coin, keypath, scriptConfig, display };
      return 'multisig' in scriptConfig
        ? 'bcrt1multisig'
        : 'policy' in scriptConfig
          ? 'bcrt1policy'
          : 'bcrt1simple';
    },
    btcSignPSBT: async (
      coin: string,
      psbt: string,
      forceScriptConfig: unknown,
      formatUnit: string
    ) => {
      client.signed = { coin, psbt, forceScriptConfig, formatUnit };
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
    expect(client.registered?.coin).toBe('rbtc');
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
      coin: 'rbtc',
      keypath: [84 + HARDENED, 1 + HARDENED, HARDENED, 0, 7],
      scriptConfig: { simpleType: 'p2wpkh' },
      display: true
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
      coin: 'rbtc',
      psbt: 'cHNidP8BAA=',
      forceScriptConfig: undefined,
      formatUnit: 'default'
    });
    expect(psbtConstructor.fromBuffer).toHaveBeenCalledWith(
      'cHNidP8BAA=:signed'
    );
    expect(psbt.combine).toHaveBeenCalledWith(signedPsbt);
  });
});
