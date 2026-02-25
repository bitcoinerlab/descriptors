// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { readFileSync } from 'fs';
import { join } from 'path';
import type { PsbtInput } from 'bip174';
import { initEccLib } from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { fromHex, toHex } from 'uint8array-tools';
import {
  isTaprootInput,
  tapleafHash,
  tapTweakHash,
  witnessStackToScriptWitness
} from '../dist/bitcoinjs-lib-internals';

// @ts-expect-error TypeScript Node10 resolution does not read package exports.
import * as bip341 from 'bitcoinjs-lib/src/payments/bip341';
// @ts-expect-error TypeScript Node10 resolution does not read package exports.
import * as bip371 from 'bitcoinjs-lib/src/psbt/bip371';
// @ts-expect-error TypeScript Node10 resolution does not read package exports.
import * as psbtUtils from 'bitcoinjs-lib/src/psbt/psbtutils';

describe('bitcoinjs-lib internals compatibility', () => {
  beforeAll(() => {
    initEccLib(ecc);
  });

  test('tapleafHash matches bitcoinjs implementation', () => {
    const vectors = [
      { output: Uint8Array.from([]), version: 0xc0 },
      { output: Uint8Array.from([0x51]), version: 0xc0 },
      { output: fromHex(`20${'11'.repeat(32)}ac`), version: 0xc0 },
      { output: fromHex(`512103${'22'.repeat(33)}51ae`), version: 0xc2 }
    ];

    vectors.forEach(vector => {
      expect(toHex(tapleafHash(vector))).toEqual(
        toHex(bip341.tapleafHash(vector))
      );
    });
  });

  test('tapTweakHash matches bitcoinjs implementation', () => {
    const internalPubkey = fromHex('11'.repeat(32));
    const merkleRoot = fromHex('22'.repeat(32));

    expect(toHex(tapTweakHash(internalPubkey, undefined))).toEqual(
      toHex(bip341.tapTweakHash(internalPubkey, undefined))
    );
    expect(toHex(tapTweakHash(internalPubkey, merkleRoot))).toEqual(
      toHex(bip341.tapTweakHash(internalPubkey, merkleRoot))
    );
  });

  test('witnessStackToScriptWitness matches bitcoinjs implementation', () => {
    const vectors = [
      [] as Uint8Array[],
      [Uint8Array.from([])],
      [fromHex('01'), fromHex('aa'.repeat(32))],
      [fromHex('00'.repeat(80)), fromHex('51')]
    ];

    vectors.forEach(vector => {
      expect(toHex(witnessStackToScriptWitness(vector))).toEqual(
        toHex(psbtUtils.witnessStackToScriptWitness(vector))
      );
    });
  });

  test('isTaprootInput matches bitcoinjs implementation', () => {
    const taprootOutputScript = fromHex(`5120${'33'.repeat(32)}`);
    const nonTaprootOutputScript = fromHex(`0014${'44'.repeat(20)}`);

    const tapLeafScript = {
      controlBlock: fromHex(`c0${'55'.repeat(32)}`),
      script: fromHex('51'),
      leafVersion: 0xc0
    };

    const tapBip32Derivation = {
      pubkey: fromHex('66'.repeat(32)),
      leafHashes: [] as Uint8Array[],
      masterFingerprint: fromHex('00000000'),
      path: 'm/0'
    };

    const cases: PsbtInput[] = [
      {},
      { tapInternalKey: fromHex('77'.repeat(32)) },
      { tapMerkleRoot: fromHex('88'.repeat(32)) },
      { tapLeafScript: [tapLeafScript] },
      { tapBip32Derivation: [tapBip32Derivation] },
      { witnessUtxo: { script: taprootOutputScript, value: 1n } },
      { witnessUtxo: { script: nonTaprootOutputScript, value: 1n } }
    ];

    cases.forEach(testCase => {
      expect(isTaprootInput(testCase)).toEqual(bip371.isTaprootInput(testCase));
    });
  });

  test('dist runtime has no bitcoinjs deep imports', () => {
    const internalsPath = join(
      __dirname,
      '..',
      'dist',
      'bitcoinjs-lib-internals.js'
    );
    const internals = readFileSync(internalsPath, 'utf8');

    expect(internals).not.toMatch(/require\(\s*['"]bitcoinjs-lib\/src\//);
    expect(internals).not.toMatch(/from\s+['"]bitcoinjs-lib\/src\//);
    expect(internals.includes('require.resolve')).toBe(false);
    expect(internals.includes('require(modulePath)')).toBe(false);
  });
});
