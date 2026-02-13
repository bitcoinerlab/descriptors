// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory } from '../dist/descriptors';
import { toHex } from 'uint8array-tools';

const { expand, ECPair } = DescriptorsFactory(ecc);

describe('miniscript expansion', () => {
  test('does not treat sha256 digest hex as a key expression', () => {
    const signer = ECPair.fromPrivateKey(new Uint8Array(32).fill(77));
    const pubkey = toHex(signer.publicKey);
    const digest = '03' + '11'.repeat(31);
    const descriptor = `wsh(and_v(v:sha256(${digest}),pk(${pubkey})))`;

    const expansion = expand({ descriptor });
    expect(expansion.expandedMiniscript).toEqual(
      `and_v(v:sha256(${digest}),pk(@0))`
    );
    expect(Object.keys(expansion.expansionMap ?? {})).toEqual(['@0']);
  });
});
