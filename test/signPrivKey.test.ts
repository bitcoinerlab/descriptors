// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { networks, signers } from '../dist';
import { createPsbt } from './helpers/psbt';

const { signPrivKey, signInputPrivKey } = signers;

describe('signPrivKey', () => {
  test('throws for bitcoinjs-lib PSBTs', () => {
    const psbt = createPsbt(false, networks.regtest);

    expect(() =>
      signPrivKey({
        psbt,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('only supported with @scure/btc-signer transactions');
  });

  test('accepts scure transactions (then fails only if no inputs exist)', () => {
    const psbt = createPsbt(true, networks.regtest);

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
    const psbt = createPsbt(false, networks.regtest);

    expect(() =>
      signInputPrivKey({
        psbt,
        index: 0,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('only supported with @scure/btc-signer transactions');
  });

  test('accepts scure transactions (then fails only if index is invalid)', () => {
    const psbt = createPsbt(true, networks.regtest);

    expect(() =>
      signInputPrivKey({
        psbt,
        index: 0,
        privKey: new Uint8Array(32).fill(1)
      })
    ).toThrow('Invalid index');
  });
});
