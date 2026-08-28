// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { networks } from '../dist';
import { DescriptorsFactory } from '../dist';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import { createScureLib } from '../dist/scure';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Transaction } from 'bitcoinjs-lib';
import { createPsbt, isScurePsbt } from './helpers/psbt';

const PUBKEY_HEX =
  '03c6e26fdf91debe78458853f1ba08d8de71b7672a099e1be5b6204dab83c046e5';

const isScure = process.env['BITCOIN_LIB'] === 'scure';
const { Output } = DescriptorsFactory(
  isScure ? createScureLib() : createBitcoinjsLib(ecc)
);

function buildOutput() {
  return new Output({
    descriptor: `wpkh(${PUBKEY_HEX})`,
    network: networks.regtest
  });
}

describe('PSBT value handling', () => {
  test('updatePsbtAsInput keeps both UTXO fields with Segwit txHex', () => {
    const output = buildOutput();
    const script = output.getScriptPubKey();
    const value = 1000n;
    const fundingTx = new Transaction();
    fundingTx.addInput(new Uint8Array(32), 0xffffffff);
    fundingTx.addOutput(script, value);
    const psbt = createPsbt(isScure, networks.regtest);

    output.updatePsbtAsInput({
      psbt,
      txHex: fundingTx.toHex(),
      vout: 0
    });

    if (isScurePsbt(psbt)) {
      const input = psbt.getInput(0);
      expect(input.nonWitnessUtxo).toBeDefined();
      expect(input.witnessUtxo).toEqual({ script, amount: value });
    } else {
      const input = psbt.data.inputs[0];
      expect(input?.nonWitnessUtxo).toBeDefined();
      expect(input?.witnessUtxo).toEqual({ script, value });
    }
  });

  test('updatePsbtAsInput adds witnessUtxo with txId and value', () => {
    const output = buildOutput();
    const psbt = createPsbt(isScure, networks.regtest);
    const value = 1000n;
    const warn = jest
      .spyOn(console, 'warn')
      .mockImplementation(() => undefined);

    output.updatePsbtAsInput({
      psbt,
      txId: '11'.repeat(32),
      vout: 0,
      value
    });

    warn.mockRestore();
    const script = output.getScriptPubKey();
    if (isScurePsbt(psbt)) {
      expect(psbt.getInput(0).witnessUtxo).toEqual({ script, amount: value });
    } else {
      expect(psbt.data.inputs[0]?.witnessUtxo).toEqual({ script, value });
    }
  });

  test('updatePsbtAsOutput rejects non-bigint values', () => {
    const output = buildOutput();
    const psbt = createPsbt(isScure, networks.regtest);
    expect(() =>
      output.updatePsbtAsOutput({
        psbt,
        value: 1000 as unknown as bigint
      })
    ).toThrow('Error: value must be a bigint');
  });

  test('updatePsbtAsOutput rejects negative bigint values', () => {
    const output = buildOutput();
    const psbt = createPsbt(isScure, networks.regtest);
    expect(() =>
      output.updatePsbtAsOutput({
        psbt,
        value: -1n
      })
    ).toThrow('Error: value must be >= 0n');
  });

  test('updatePsbtAsInput rejects non-bigint values', () => {
    const output = buildOutput();
    const psbt = createPsbt(isScure, networks.regtest);
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
    const psbt = createPsbt(isScure, networks.regtest);
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
