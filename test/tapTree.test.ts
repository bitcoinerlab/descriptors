// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { createHash } from 'crypto';
import {
  parseTapTreeExpression,
  selectTapLeafCandidates
} from '../dist/tapTree';
import type { TapLeafSelection } from '../dist/tapTree';
import type { TapBip32Derivation } from 'bip174/src/lib/interfaces';
import { DescriptorsFactory } from '../dist/descriptors';
import {
  buildTaprootBip32Derivations,
  buildTapLeafScripts,
  buildTaprootLeafPsbtMetadata,
  satisfyTapTree
} from '../dist/tapMiniscript';
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
  const INTERNAL_KEY =
    'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
  const LEAF_KEY_1 =
    '669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0';
  const LEAF_KEY_2 =
    'e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13';
  const XPUB_1 =
    'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL';
  const XPUB_2 =
    'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y';

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

  test('builds tapTreeInfo for Output (task 6)', () => {
    const { Output } = DescriptorsFactory(ecc);
    const output = new Output({
      descriptor:
        'tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))'
    });
    const { tapTreeInfo } = output.expand();
    expect(tapTreeInfo).toBeDefined();
  });

  test('builds PSBT taproot leaf metadata for all leaves', () => {
    const { expand } = DescriptorsFactory(ecc);
    const descriptor = `tr(${INTERNAL_KEY},{pk(${LEAF_KEY_1}),pk(${LEAF_KEY_2})})`;
    const { tapTreeInfo, expansionMap } = expand({ descriptor });
    if (!tapTreeInfo) throw new Error('tapTreeInfo not available');
    const internalPubkey = expansionMap?.['@0']?.pubkey;
    if (!internalPubkey) throw new Error('internal pubkey not available');

    const metadata = buildTaprootLeafPsbtMetadata({
      tapTreeInfo,
      internalPubkey
    });
    //console.log(JSON.stringify(metadata, null, 2));
    expect(metadata).toHaveLength(2);
    const hashes = new Set(
      metadata.map(entry => entry.tapLeafHash.toString('hex'))
    );
    expect(hashes.size).toBe(2);
    metadata.forEach(entry => {
      expect(entry.controlBlock.length).toBe(65);
      expect((entry.controlBlock.length - 33) % 32).toBe(0);
    });

    const tapLeafScripts = buildTapLeafScripts({ tapTreeInfo, internalPubkey });
    expect(tapLeafScripts).toHaveLength(2);
    tapLeafScripts.forEach(entry => {
      expect(entry.script.length).toBeGreaterThan(0);
      expect(entry.controlBlock.length).toBe(65);
      expect(entry.leafVersion).toBe(0xc0);
    });
  });

  test('builds tapBip32Derivation entries with leafHashes for script keys', () => {
    const { expand } = DescriptorsFactory(ecc);
    const internal = `[00000000/111'/222']${XPUB_1}/0`;
    const leaf1 = `[00000000/111'/222']${XPUB_1}/1`;
    const leaf2 = `[11111111/44'/0'/0']${XPUB_2}/0`;
    const descriptor = `tr(${internal},{pk(${leaf1}),pk(${leaf2})})`;
    const { tapTreeInfo, expansionMap } = expand({ descriptor });
    if (!tapTreeInfo || !expansionMap)
      throw new Error('tapTree data not available');
    const internalKeyInfo = expansionMap['@0'];
    if (!internalKeyInfo) throw new Error('internal key info not available');

    const derivations = buildTaprootBip32Derivations({
      tapTreeInfo,
      internalKeyInfo
    });
    expect(derivations).toHaveLength(3);

    const internalPubkey = expansionMap['@0']?.pubkey;
    if (!internalPubkey) throw new Error('expected internal pubkey');

    const derivationByPubkey = new Map<string, TapBip32Derivation>(
      derivations.map((derivation: TapBip32Derivation) => [
        derivation.pubkey.toString('hex'),
        derivation
      ])
    );

    const internalDerivation = derivationByPubkey.get(
      internalPubkey.toString('hex')
    );
    expect(internalDerivation).toBeDefined();
    expect(internalDerivation?.leafHashes).toHaveLength(0);

    const scriptDerivations = derivations.filter(
      entry => !entry.pubkey.equals(internalPubkey)
    );
    expect(scriptDerivations).toHaveLength(2);
    scriptDerivations.forEach(entry => {
      expect(entry.leafHashes).toHaveLength(1);
    });
  });

  test('fails fast when script policy is used on key-only taproot', () => {
    const { Output } = DescriptorsFactory(ecc);
    expect(
      () =>
        new Output({
          descriptor: `tr(${INTERNAL_KEY})`,
          taprootSpendPath: 'script'
        })
    ).toThrow('taprootSpendPath=script requires a tr(KEY,TREE) descriptor');
  });

  test('fails fast when script policy is used on addr(TR_ADDRESS)', () => {
    const { Output } = DescriptorsFactory(ecc);
    const keyOutput = new Output({ descriptor: `tr(${INTERNAL_KEY})` });
    const trAddress = keyOutput.getAddress();
    expect(
      () =>
        new Output({
          descriptor: `addr(${trAddress})`,
          taprootSpendPath: 'script'
        })
    ).toThrow('taprootSpendPath=script requires a tr(KEY,TREE) descriptor');
  });
});

describe('taproot tree satisfactions', () => {
  const INTERNAL_KEY =
    'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
  const LEAF_KEY =
    '669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0';
  const PREIMAGE = Buffer.alloc(32, 1);
  const DIGEST = createHash('sha256').update(PREIMAGE).digest('hex');
  const DIGEST_EXPR = `sha256(${DIGEST})`;

  const TREE_EXPRESSION = `{and_v(v:pk(${LEAF_KEY}),${DIGEST_EXPR}),pk(${LEAF_KEY})}`;
  const DESCRIPTOR = `tr(${INTERNAL_KEY},${TREE_EXPRESSION})`;

  const buildTapTreeInfo = () => {
    const { expand } = DescriptorsFactory(ecc);
    const { tapTreeInfo } = expand({ descriptor: DESCRIPTOR });
    if (!tapTreeInfo) throw new Error('tapTreeInfo not available');
    return tapTreeInfo;
  };

  test('auto-selects the smallest witness leaf', () => {
    const tapTreeInfo = buildTapTreeInfo();
    const signatures = [
      {
        pubkey: Buffer.from(LEAF_KEY, 'hex'),
        signature: Buffer.alloc(64, 2)
      }
    ];
    const best = satisfyTapTree({
      tapTreeInfo,
      signatures,
      preimages: [
        {
          digest: DIGEST_EXPR,
          preimage: PREIMAGE.toString('hex')
        }
      ]
    });
    expect(best.leaf.miniscript).toEqual(`pk(${LEAF_KEY})`);
  });

  test('selects leaf by tapLeafHash', () => {
    const tapTreeInfo = buildTapTreeInfo();
    const candidates = selectTapLeafCandidates({ tapTreeInfo });
    const target = candidates.find((entry: TapLeafSelection) =>
      entry.leaf.miniscript.startsWith('and_v(')
    );
    if (!target) throw new Error('target leaf not found');
    const signatures = [
      {
        pubkey: Buffer.from(LEAF_KEY, 'hex'),
        signature: Buffer.alloc(64, 2)
      }
    ];
    const best = satisfyTapTree({
      tapTreeInfo,
      signatures,
      tapLeaf: target.tapLeafHash,
      preimages: [
        {
          digest: DIGEST_EXPR,
          preimage: PREIMAGE.toString('hex')
        }
      ]
    });
    expect(best.leaf.miniscript.startsWith('and_v(')).toBe(true);
    const hasPreimage = best.stackItems.some((item: Buffer) =>
      item.equals(PREIMAGE)
    );
    expect(hasPreimage).toBe(true);
  });

  test('throws when miniscript selector is ambiguous', () => {
    const { expand } = DescriptorsFactory(ecc);
    const duplicateDescriptor = `tr(${INTERNAL_KEY},{pk(${LEAF_KEY}),pk(${LEAF_KEY})})`;
    const { tapTreeInfo } = expand({ descriptor: duplicateDescriptor });
    if (!tapTreeInfo) throw new Error('tapTreeInfo not available');
    const signatures = [
      {
        pubkey: Buffer.from(LEAF_KEY, 'hex'),
        signature: Buffer.alloc(64, 2)
      }
    ];
    expect(() =>
      satisfyTapTree({
        tapTreeInfo,
        signatures,
        tapLeaf: `pk(${LEAF_KEY})`,
        preimages: []
      })
    ).toThrow('ambiguous');
  });
});
