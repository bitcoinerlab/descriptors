// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { parseTapTreeExpression } from '../dist/tapTree';
import { DescriptorsFactory } from '../dist/descriptors';
import * as ecc from '@bitcoinerlab/secp256k1';

describe('taproot tree parser', () => {
  test('parses a leaf miniscript expression', () => {
    expect(parseTapTreeExpression('pk(@0)')).toEqual({ miniscript: 'pk(@0)' });
  });

  test('parses a simple branch', () => {
    expect(parseTapTreeExpression('{pk(@0),pk(@1)}')).toEqual({
      left: { miniscript: 'pk(@0)' },
      right: { miniscript: 'pk(@1)' }
    });
  });

  test('parses a nested branch', () => {
    expect(parseTapTreeExpression('{pk(@0),{pk(@1),pk(@2)}}')).toEqual({
      left: { miniscript: 'pk(@0)' },
      right: { left: { miniscript: 'pk(@1)' }, right: { miniscript: 'pk(@2)' } }
    });
  });
});

describe('taproot tree compilation', () => {
  test('builds tapTreeInfo via expand for tr(KEY,TREE)', () => {
    const { expand } = DescriptorsFactory(ecc);
    const { tapTreeInfo } = expand({
      descriptor:
        'tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))'
    });
    expect(tapTreeInfo).toBeDefined();
    if (!tapTreeInfo || !('miniscript' in tapTreeInfo))
      throw new Error('tapTreeInfo leaf not available');
    expect(tapTreeInfo.miniscript).toEqual(
      'pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0)'
    );
    expect(tapTreeInfo.expandedMiniscript).toEqual('pk(@0)');
    expect(tapTreeInfo.tapScript).toBeInstanceOf(Buffer);
    expect(tapTreeInfo.tapScript.length).toBeGreaterThan(0);
  });

  test.skip('builds tapTreeInfo for Output (task 6)', () => {
    const { Output } = DescriptorsFactory(ecc);
    const output = new Output({
      descriptor:
        'tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))'
    });
    const { tapTreeInfo } = output.expand();
    expect(tapTreeInfo).toBeDefined();
  });
});
