// Distributed under the MIT software license

import { createHash } from 'crypto';
import { encodingLength } from 'varuint-bitcoin';
import type { PartialSig } from 'bip174/src/lib/interfaces';
import { DescriptorsFactory } from '../dist/descriptors';
import { selectTapLeafCandidates } from '../dist/tapTree';
import * as ecc from '@bitcoinerlab/secp256k1';

const { Output, expand } = DescriptorsFactory(ecc);

const INTERNAL_KEY =
  'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
const LEAF_KEY =
  '669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0';
const COMPRESSED_KEY =
  '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';
const PREIMAGE = Buffer.alloc(32, 1);
const DIGEST = createHash('sha256').update(PREIMAGE).digest('hex');
const DIGEST_EXPR = `sha256(${DIGEST})`;
const SCRIPT_LEAF_EXPR = `and_v(v:pk(${LEAF_KEY}),${DIGEST_EXPR})`;
const KEY_LEAF_EXPR = `pk(${LEAF_KEY})`;
const TREE_EXPRESSION = `{${SCRIPT_LEAF_EXPR},${KEY_LEAF_EXPR}}`;
const TR_KEY_DESCRIPTOR = `tr(${INTERNAL_KEY})`;
const TR_TREE_DESCRIPTOR = `tr(${INTERNAL_KEY},${TREE_EXPRESSION})`;
const FAKE_SIGNATURES = 'DANGEROUSLY_USE_FAKE_SIGNATURES' as const;

const preimages = [
  {
    digest: DIGEST_EXPR,
    preimage: PREIMAGE.toString('hex')
  }
];

const taprootKeyPathWeight = (signatureLength: number) =>
  41 * 4 +
  encodingLength(1) +
  encodingLength(signatureLength) +
  signatureLength;

describe('taproot inputWeight', () => {
  test('tr(KEY): fake signatures use configured taproot sighash size', () => {
    const output = new Output({ descriptor: TR_KEY_DESCRIPTOR });

    expect(output.inputWeight(true, FAKE_SIGNATURES)).toBe(
      taprootKeyPathWeight(64)
    );

    expect(
      output.inputWeight(true, FAKE_SIGNATURES, {
        taprootSighash: 'non-SIGHASH_DEFAULT'
      })
    ).toBe(taprootKeyPathWeight(65));
  });

  test('tr(KEY): real signatures use actual 64/65 byte length', () => {
    const output = new Output({ descriptor: TR_KEY_DESCRIPTOR });

    const signatures64: PartialSig[] = [
      {
        pubkey: Buffer.from(INTERNAL_KEY, 'hex'),
        signature: Buffer.alloc(64, 1)
      }
    ];
    const signatures65: PartialSig[] = [
      {
        pubkey: Buffer.from(INTERNAL_KEY, 'hex'),
        signature: Buffer.alloc(65, 1)
      }
    ];

    expect(output.inputWeight(true, signatures64)).toBe(
      taprootKeyPathWeight(64)
    );
    expect(output.inputWeight(true, signatures65)).toBe(
      taprootKeyPathWeight(65)
    );
  });

  test('addr(TR_ADDRESS): behaves as key-path taproot', () => {
    const trOutput = new Output({ descriptor: TR_KEY_DESCRIPTOR });
    const addressOutput = new Output({
      descriptor: `addr(${trOutput.getAddress()})`
    });

    expect(addressOutput.inputWeight(true, FAKE_SIGNATURES)).toBe(
      taprootKeyPathWeight(64)
    );
    expect(
      addressOutput.inputWeight(true, FAKE_SIGNATURES, {
        taprootSighash: 'non-SIGHASH_DEFAULT'
      })
    ).toBe(taprootKeyPathWeight(65));
  });

  test('tr(KEY,TREE): key policy uses key-path sizing', () => {
    const keyOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'key',
      preimages
    });

    expect(keyOutput.inputWeight(true, FAKE_SIGNATURES)).toBe(
      taprootKeyPathWeight(64)
    );
  });

  test('tr(KEY,TREE): script policy uses script-path sizing', () => {
    const keyOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'key',
      preimages
    });
    const scriptOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'script',
      preimages
    });

    const keyWeight = keyOutput.inputWeight(true, FAKE_SIGNATURES);
    const scriptWeight = scriptOutput.inputWeight(true, FAKE_SIGNATURES);

    expect(scriptWeight).toBeGreaterThan(keyWeight);
  });

  test('tr(KEY,TREE): tapLeaf selector (string/hash) controls script estimate', () => {
    const { tapTreeInfo } = expand({ descriptor: TR_TREE_DESCRIPTOR });
    if (!tapTreeInfo) throw new Error('tapTreeInfo not available');
    const scriptLeafSelection = selectTapLeafCandidates({
      tapTreeInfo,
      tapLeaf: SCRIPT_LEAF_EXPR
    })[0];
    if (!scriptLeafSelection) throw new Error('script leaf not found');

    const autoOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'script',
      preimages
    });
    const keyLeafOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'script',
      tapLeaf: KEY_LEAF_EXPR,
      preimages
    });
    const scriptLeafByExprOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'script',
      tapLeaf: SCRIPT_LEAF_EXPR,
      preimages
    });
    const scriptLeafByHashOutput = new Output({
      descriptor: TR_TREE_DESCRIPTOR,
      taprootSpendPath: 'script',
      tapLeaf: scriptLeafSelection.tapLeafHash,
      preimages
    });

    const autoWeight = autoOutput.inputWeight(true, FAKE_SIGNATURES);
    const keyLeafWeight = keyLeafOutput.inputWeight(true, FAKE_SIGNATURES);
    const scriptLeafByExprWeight = scriptLeafByExprOutput.inputWeight(
      true,
      FAKE_SIGNATURES
    );
    const scriptLeafByHashWeight = scriptLeafByHashOutput.inputWeight(
      true,
      FAKE_SIGNATURES
    );

    expect(autoWeight).toBe(keyLeafWeight);
    expect(scriptLeafByExprWeight).toBe(scriptLeafByHashWeight);
    expect(scriptLeafByExprWeight).toBeGreaterThan(keyLeafWeight);
  });

  test('fails fast for incompatible taproot policy/selector params', () => {
    expect(
      () =>
        new Output({
          descriptor: TR_KEY_DESCRIPTOR,
          taprootSpendPath: 'script'
        })
    ).toThrow('taprootSpendPath=script requires a tr(KEY,TREE) descriptor');

    const keyOutput = new Output({ descriptor: TR_KEY_DESCRIPTOR });
    expect(
      () =>
        new Output({
          descriptor: `addr(${keyOutput.getAddress()})`,
          taprootSpendPath: 'script'
        })
    ).toThrow('taprootSpendPath=script requires a tr(KEY,TREE) descriptor');

    expect(
      () =>
        new Output({
          descriptor: TR_TREE_DESCRIPTOR,
          taprootSpendPath: 'key',
          tapLeaf: KEY_LEAF_EXPR
        })
    ).toThrow('tapLeaf cannot be used when taprootSpendPath is key');

    expect(
      () =>
        new Output({
          descriptor: `wpkh(${COMPRESSED_KEY})`,
          taprootSpendPath: 'key'
        })
    ).toThrow('taprootSpendPath/tapLeaf require a taproot descriptor');
  });

  test('throws on non-segwit transaction flag for taproot inputs', () => {
    const output = new Output({ descriptor: TR_KEY_DESCRIPTOR });
    expect(() => output.inputWeight(false, FAKE_SIGNATURES)).toThrow(
      'a tx is segwit'
    );
  });
});
