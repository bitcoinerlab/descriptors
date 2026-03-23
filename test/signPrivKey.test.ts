// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { networks, signers } from '../dist';
import type { ScureTransactionLike } from '../dist/bitcoinLib';
import { createPsbt } from './helpers/psbt';

const { signPrivKey, signInputPrivKey, signECPair, signInputECPair } = signers;

const testECPair = {
  publicKey: new Uint8Array(33).fill(2),
  sign: (_hash: Uint8Array, _lowR?: boolean) => new Uint8Array(64),
  verify: (_hash: Uint8Array, _signature: Uint8Array) => true,
  tweak: (_tweak: Uint8Array) => testECPair
};

describe('signPrivKey', () => {
  test('throws for bitcoinjs-lib PSBTs', () => {
    const psbt = createPsbt(
      false,
      networks.regtest
    ) as unknown as ScureTransactionLike;

    expect(() =>
      signPrivKey({
        psbt,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('only supported with @scure/btc-signer transactions');
  });

  test('accepts scure transactions (then fails only if no inputs exist)', () => {
    const psbt = createPsbt(true, networks.regtest) as ScureTransactionLike;

    expect(() =>
      signPrivKey({
        psbt,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('No inputs were signed');
  });
});

describe('signInputPrivKey', () => {
  test('throws for bitcoinjs-lib PSBTs', () => {
    const psbt = createPsbt(
      false,
      networks.regtest
    ) as unknown as ScureTransactionLike;

    expect(() =>
      signInputPrivKey({
        psbt,
        index: 0,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('only supported with @scure/btc-signer transactions');
  });

  test('accepts scure transactions (then fails only if index is invalid)', () => {
    const psbt = createPsbt(true, networks.regtest) as ScureTransactionLike;

    expect(() =>
      signInputPrivKey({
        psbt,
        index: 0,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('Invalid index');
  });
});

describe('signECPair', () => {
  test('throws for scure transactions', () => {
    const psbt = createPsbt(true, networks.regtest) as unknown as Parameters<
      typeof signECPair
    >[0]['psbt'];

    expect(() =>
      signECPair({
        psbt,
        ecpair: testECPair
      })
    ).toThrow('only supported with bitcoinjs-lib PSBTs');
  });
});

describe('signInputECPair', () => {
  test('throws for scure transactions', () => {
    const psbt = createPsbt(true, networks.regtest) as unknown as Parameters<
      typeof signInputECPair
    >[0]['psbt'];

    expect(() =>
      signInputECPair({
        psbt,
        index: 0,
        ecpair: testECPair
      })
    ).toThrow('only supported with bitcoinjs-lib PSBTs');
  });
});
