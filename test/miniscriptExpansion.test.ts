// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { DescriptorsFactory } from '../dist/descriptors';
import { createScureLib } from '../dist/scure';
import * as ecc from '@bitcoinerlab/secp256k1';
import { toHex } from 'uint8array-tools';
import { createPrivKeySigner, getPubKey } from './helpers/keys';

const isScure = process.env['BITCOIN_LIB'] === 'scure';
const { expand } = DescriptorsFactory(isScure ? createScureLib(ecc) : ecc);

describe('miniscript expansion', () => {
  test('does not treat sha256 digest hex as a key expression', () => {
    const signer = createPrivKeySigner(new Uint8Array(32).fill(77), isScure);
    const pubkey = toHex(getPubKey(signer));
    const digest = '03' + '11'.repeat(31);
    const descriptor = `wsh(and_v(v:sha256(${digest}),pk(${pubkey})))`;

    const expansion = expand({ descriptor });
    expect(expansion.expandedMiniscript).toEqual(
      `and_v(v:sha256(${digest}),pk(@0))`
    );
    expect(Object.keys(expansion.expansionMap ?? {})).toEqual(['@0']);
  });
});
