// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { networks, Psbt } from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory } from '../dist';

const PUBKEY_HEX =
  '03c6e26fdf91debe78458853f1ba08d8de71b7672a099e1be5b6204dab83c046e5';

const { Output } = DescriptorsFactory(ecc);

function buildOutput() {
  return new Output({
    descriptor: `wpkh(${PUBKEY_HEX})`,
    network: networks.regtest
  });
}

describe('Bigint value runtime guards', () => {
  test('updatePsbtAsOutput rejects non-bigint values', () => {
    const output = buildOutput();
    const psbt = new Psbt({ network: networks.regtest });
    expect(() =>
      output.updatePsbtAsOutput({
        psbt,
        value: 1000 as unknown as bigint
      })
    ).toThrow('Error: value must be a bigint');
  });

  test('updatePsbtAsOutput rejects negative bigint values', () => {
    const output = buildOutput();
    const psbt = new Psbt({ network: networks.regtest });
    expect(() =>
      output.updatePsbtAsOutput({
        psbt,
        value: -1n
      })
    ).toThrow('Error: value must be >= 0n');
  });

  test('updatePsbtAsInput rejects non-bigint values', () => {
    const output = buildOutput();
    const psbt = new Psbt({ network: networks.regtest });
    expect(() =>
      output.updatePsbtAsInput({
        psbt,
        txId: '11'.repeat(32),
        vout: 0,
        value: 1000 as unknown as bigint
      })
    ).toThrow('Error: value must be a bigint');
  });

  test('updatePsbtAsInput rejects negative bigint values', () => {
    const output = buildOutput();
    const psbt = new Psbt({ network: networks.regtest });
    expect(() =>
      output.updatePsbtAsInput({
        psbt,
        txId: '11'.repeat(32),
        vout: 0,
        value: -1n
      })
    ).toThrow('Error: value must be >= 0n');
  });
});
