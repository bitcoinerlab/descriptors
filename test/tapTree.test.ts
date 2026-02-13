// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { createHash } from 'crypto';
import {
  parseTapTreeExpression,
  selectTapLeafCandidates
} from '../dist/tapTree';
import type { TapLeafSelection } from '../dist/tapTree';
import type { TapBip32Derivation } from 'bip174';
import { Psbt, Transaction } from 'bitcoinjs-lib';
import { DescriptorsFactory } from '../dist/descriptors';
import { signInputECPair } from '../dist/signers';
import {
  buildTaprootBip32Derivations,
  buildTaprootLeafPsbtMetadata,
  satisfyTapTree
} from '../dist/tapMiniscript';
import * as ecc from '@bitcoinerlab/secp256k1';
import { compare, fromHex, toHex } from 'uint8array-tools';

function createNextSigner<T>(
  ECPair: {
    fromPrivateKey: (privateKey: Uint8Array) => T;
  },
  startSeed = 1
): () => T {
  // Deterministic distinct keys for reproducible tests.
  let seed = startSeed;
  return () => ECPair.fromPrivateKey(new Uint8Array(32).fill(seed++));
}

describe('taproot tree parser', () => {
  test('parses a leaf miniscript expression', () => {
    expect(parseTapTreeExpression('pk(@0)')).toEqual({ expression: 'pk(@0)' });
  });

  test('parses a simple branch', () => {
    expect(parseTapTreeExpression('{pk(@0),pk(@1)}')).toEqual({
      left: { expression: 'pk(@0)' },
      right: { expression: 'pk(@1)' }
    });
  });

  test('parses a nested branch', () => {
    expect(parseTapTreeExpression('{pk(@0),{pk(@1),pk(@2)}}')).toEqual({
      left: { expression: 'pk(@0)' },
      right: { left: { expression: 'pk(@1)' }, right: { expression: 'pk(@2)' } }
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

  const xOnly = (pubkey: Uint8Array): string => toHex(pubkey.slice(1, 33));

  const buildFundingTxHex = (
    scriptPubKey: Uint8Array,
    value = 50000n
  ): string => {
    const tx = new Transaction();
    tx.addInput(new Uint8Array(32), 0);
    tx.addOutput(scriptPubKey, value);
    return tx.toHex();
  };

  test('builds tapTreeInfo via expand for tr(KEY,TREE)', () => {
    const { expand } = DescriptorsFactory(ecc);
    const { tapTreeInfo } = expand({
      descriptor:
        'tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0))'
    });
    expect(tapTreeInfo).toBeDefined();
    if (!tapTreeInfo || !('expression' in tapTreeInfo))
      throw new Error('tapTreeInfo leaf not available');
    expect(tapTreeInfo.expression).toEqual(
      'pk(669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0)'
    );
    expect(tapTreeInfo.expandedExpression).toEqual('pk(@0)');
    expect(tapTreeInfo.expandedMiniscript).toEqual('pk(@0)');
    expect(tapTreeInfo.tapScript).toBeInstanceOf(Uint8Array);
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
    const hashes = new Set(metadata.map(entry => toHex(entry.tapLeafHash)));
    expect(hashes.size).toBe(2);
    metadata.forEach(entry => {
      expect(entry.controlBlock.length).toBe(65);
      expect((entry.controlBlock.length - 33) % 32).toBe(0);
    });

    const tapLeafScripts = metadata.map(({ leaf, controlBlock }) => ({
      script: leaf.tapScript,
      leafVersion: leaf.version,
      controlBlock
    }));
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
        toHex(derivation.pubkey),
        derivation
      ])
    );

    const internalDerivation = derivationByPubkey.get(toHex(internalPubkey));
    expect(internalDerivation).toBeDefined();
    expect(internalDerivation?.leafHashes).toHaveLength(0);

    const scriptDerivations = derivations.filter(
      entry => compare(entry.pubkey, internalPubkey) !== 0
    );
    expect(scriptDerivations).toHaveLength(2);
    scriptDerivations.forEach(entry => {
      expect(entry.leafHashes).toHaveLength(1);
    });
  });

  test('updatePsbtAsInput populates taproot script-path PSBT fields', () => {
    const { Output } = DescriptorsFactory(ecc);
    const internal = `[00000000/111'/222']${XPUB_1}/0`;
    const leaf1 = `[00000000/111'/222']${XPUB_1}/1`;
    const leaf2 = `[11111111/44'/0'/0']${XPUB_2}/0`;
    const descriptor = `tr(${internal},{pk(${leaf1}),pk(${leaf2})})`;
    const output = new Output({
      descriptor,
      taprootSpendPath: 'script'
    });
    const psbt = new Psbt();
    output.updatePsbtAsInput({
      psbt,
      txId: '11'.repeat(32),
      value: 50000n,
      vout: 0
    });

    const input = psbt.data.inputs[0];
    if (!input) throw new Error('missing psbt input');
    expect(input.tapInternalKey).toBeInstanceOf(Uint8Array);
    expect(input.tapInternalKey?.length).toBe(32);
    expect(input.tapLeafScript).toBeDefined();
    expect(input.tapLeafScript).toHaveLength(2);
    input.tapLeafScript?.forEach(entry => {
      expect(entry.script.length).toBeGreaterThan(0);
      expect(entry.controlBlock.length).toBe(65);
    });
    expect(input.tapBip32Derivation).toBeDefined();
    expect(input.tapBip32Derivation).toHaveLength(3);

    const internalPubkey = output.expand().expansionMap?.['@0']?.pubkey;
    if (!internalPubkey) throw new Error('expected internal pubkey');
    const internalDerivation = input.tapBip32Derivation?.find(
      entry => compare(entry.pubkey, internalPubkey) === 0
    );
    expect(internalDerivation?.leafHashes).toHaveLength(0);
    const scriptDerivations =
      input.tapBip32Derivation?.filter(
        entry => compare(entry.pubkey, internalPubkey) !== 0
      ) || [];
    expect(scriptDerivations).toHaveLength(2);
    scriptDerivations.forEach(entry => {
      expect(entry.leafHashes).toHaveLength(1);
    });
  });

  test('updatePsbtAsInput in key policy does not add tapLeafScript', () => {
    const { Output } = DescriptorsFactory(ecc);
    const internal = `[00000000/111'/222']${XPUB_1}/0`;
    const leaf1 = `[00000000/111'/222']${XPUB_1}/1`;
    const leaf2 = `[11111111/44'/0'/0']${XPUB_2}/0`;
    const descriptor = `tr(${internal},{pk(${leaf1}),pk(${leaf2})})`;
    const output = new Output({
      descriptor,
      taprootSpendPath: 'key'
    });
    const psbt = new Psbt();
    output.updatePsbtAsInput({
      psbt,
      txId: '22'.repeat(32),
      value: 50000n,
      vout: 0
    });

    const input = psbt.data.inputs[0];
    if (!input) throw new Error('missing psbt input');
    expect(input.tapLeafScript).toBeUndefined();
  });

  test('script policy signs and finalizes through script-path', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const internalSigner = nextSigner();
    const leafSignerA = nextSigner();
    const leafSignerB = nextSigner();
    const leafA = `pk(${xOnly(leafSignerA.publicKey)})`;
    const leafB = `pk(${xOnly(leafSignerB.publicKey)})`;
    const descriptor = `tr(${xOnly(internalSigner.publicKey)},{${leafA},${leafB}})`;
    const output = new Output({
      descriptor,
      taprootSpendPath: 'script',
      tapLeaf: leafA
    });

    const txHex = buildFundingTxHex(output.getScriptPubKey());
    const psbt = new Psbt();
    const finalize = output.updatePsbtAsInput({ psbt, txHex, vout: 0 });
    psbt.addOutput({ script: Uint8Array.from([0x51]), value: 40000n });

    signInputECPair({ psbt, index: 0, ecpair: leafSignerA });
    finalize({ psbt });

    const witness = psbt.extractTransaction().ins[0]?.witness;
    if (!witness) throw new Error('witness not available');
    expect(witness.length).toBeGreaterThanOrEqual(3);
    const controlBlock = witness[witness.length - 1];
    if (!controlBlock) throw new Error('missing control block');
    expect(controlBlock.length).toBe(65);
  });

  test('script policy finalizer requires tapScriptSig', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const internalSigner = nextSigner();
    const leafSigner = nextSigner();
    const leaf = `pk(${xOnly(leafSigner.publicKey)})`;
    const descriptor = `tr(${xOnly(internalSigner.publicKey)},${leaf})`;
    const output = new Output({
      descriptor,
      taprootSpendPath: 'script',
      tapLeaf: leaf
    });

    const txHex = buildFundingTxHex(output.getScriptPubKey());
    const psbt = new Psbt();
    const finalize = output.updatePsbtAsInput({ psbt, txHex, vout: 0 });
    psbt.addOutput({ script: Uint8Array.from([0x51]), value: 40000n });

    expect(() => finalize({ psbt, validate: false })).toThrow(
      'cannot finalize taproot script-path without tapScriptSig'
    );
  });

  test('key-path taproot signs and finalizes without tapLeafScript', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const signer = nextSigner();
    const descriptor = `tr(${xOnly(signer.publicKey)})`;
    const output = new Output({ descriptor });

    const txHex = buildFundingTxHex(output.getScriptPubKey());
    const psbt = new Psbt();
    const finalize = output.updatePsbtAsInput({ psbt, txHex, vout: 0 });
    psbt.addOutput({ script: Uint8Array.from([0x51]), value: 40000n });

    const input = psbt.data.inputs[0];
    if (!input) throw new Error('missing psbt input');
    expect(input.tapLeafScript).toBeUndefined();

    signInputECPair({ psbt, index: 0, ecpair: signer });
    finalize({ psbt });

    const witness = psbt.extractTransaction().ins[0]?.witness;
    if (!witness) throw new Error('witness not available');
    expect(witness.length).toBe(1);
  });

  test('supports sortedmulti_a() as a taproot leaf expression', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const internalSigner = nextSigner();
    const signerA = nextSigner();
    const signerB = nextSigner();
    const internalKey = xOnly(internalSigner.publicKey);
    const keyA = xOnly(signerA.publicKey);
    const keyB = xOnly(signerB.publicKey);

    const leafAB = `sortedmulti_a(1,${keyA},${keyB})`;
    const leafBA = `sortedmulti_a(1,${keyB},${keyA})`;

    const outputAB = new Output({
      descriptor: `tr(${internalKey},${leafAB})`,
      taprootSpendPath: 'script',
      tapLeaf: leafAB
    });
    const outputBA = new Output({
      descriptor: `tr(${internalKey},${leafBA})`,
      taprootSpendPath: 'script',
      tapLeaf: leafBA
    });

    expect(outputAB.getAddress()).toEqual(outputBA.getAddress());

    const tapTreeInfoAB = outputAB.expand().tapTreeInfo;
    const tapTreeInfoBA = outputBA.expand().tapTreeInfo;
    if (
      !tapTreeInfoAB ||
      !('tapScript' in tapTreeInfoAB) ||
      !tapTreeInfoBA ||
      !('tapScript' in tapTreeInfoBA)
    )
      throw new Error('tapTreeInfo leaf not available');
    expect(tapTreeInfoAB.expandedExpression).toEqual('sortedmulti_a(1,@0,@1)');
    expect(tapTreeInfoBA.expandedExpression).toEqual('sortedmulti_a(1,@0,@1)');
    expect(tapTreeInfoAB.expandedMiniscript).toBeUndefined();
    expect(tapTreeInfoBA.expandedMiniscript).toBeUndefined();
    expect(compare(tapTreeInfoAB.tapScript, tapTreeInfoBA.tapScript)).toBe(0);

    const satisfaction = outputBA.getTapScriptSatisfaction([
      {
        pubkey: signerA.publicKey.slice(1, 33),
        signature: new Uint8Array(64).fill(4)
      }
    ]);
    expect(satisfaction.stackItems.length).toBeGreaterThan(0);
  });

  test('rejects sortedmulti_a() when nested inside miniscript', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const internalSigner = nextSigner();
    const signerA = nextSigner();
    const signerB = nextSigner();
    const internalKey = xOnly(internalSigner.publicKey);
    const keyA = xOnly(signerA.publicKey);
    const keyB = xOnly(signerB.publicKey);

    expect(
      () =>
        new Output({
          descriptor: `tr(${internalKey},and_v(v:pk(${keyA}),sortedmulti_a(1,${keyA},${keyB})))`,
          taprootSpendPath: 'script'
        })
    ).toThrow('sortedmulti_a() must be a standalone taproot leaf expression');
  });

  test('rejects sortedmulti_a() outside tr()', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const signerA = nextSigner();
    const signerB = nextSigner();
    const keyA = toHex(signerA.publicKey);
    const keyB = toHex(signerB.publicKey);

    expect(
      () => new Output({ descriptor: `wsh(sortedmulti_a(1,${keyA},${keyB}))` })
    ).toThrow('Unknown miniscript fragment: sortedmulti_a');
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
  const PREIMAGE = new Uint8Array(32).fill(1);
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
        pubkey: fromHex(LEAF_KEY),
        signature: new Uint8Array(64).fill(2)
      }
    ];
    const best = satisfyTapTree({
      tapTreeInfo,
      signatures,
      preimages: [
        {
          digest: DIGEST_EXPR,
          preimage: toHex(PREIMAGE)
        }
      ]
    });
    expect(best.leaf.expression).toEqual(`pk(${LEAF_KEY})`);
  });

  test('selects leaf by tapLeafHash', () => {
    const tapTreeInfo = buildTapTreeInfo();
    const candidates = selectTapLeafCandidates({ tapTreeInfo });
    const target = candidates.find((entry: TapLeafSelection) =>
      entry.leaf.expression.startsWith('and_v(')
    );
    if (!target) throw new Error('target leaf not found');
    const signatures = [
      {
        pubkey: fromHex(LEAF_KEY),
        signature: new Uint8Array(64).fill(2)
      }
    ];
    const best = satisfyTapTree({
      tapTreeInfo,
      signatures,
      tapLeaf: target.tapLeafHash,
      preimages: [
        {
          digest: DIGEST_EXPR,
          preimage: toHex(PREIMAGE)
        }
      ]
    });
    expect(best.leaf.expression.startsWith('and_v(')).toBe(true);
    const hasPreimage = best.stackItems.some(
      (item: Uint8Array) => compare(item, PREIMAGE) === 0
    );
    expect(hasPreimage).toBe(true);
  });

  test('accepts push-only OP_1 selectors in taproot satisfactions', () => {
    const { Output, ECPair } = DescriptorsFactory(ecc);
    const nextSigner = createNextSigner(ECPair);
    const internalSigner = nextSigner();
    const signerA = nextSigner();
    const signerB = nextSigner();
    const internalKey = toHex(internalSigner.publicKey.slice(1, 33));
    const keyA = toHex(signerA.publicKey.slice(1, 33));
    const keyB = toHex(signerB.publicKey.slice(1, 33));
    const tapLeaf = `or_i(pk(${keyA}),pk(${keyB}))`;

    const output = new Output({
      descriptor: `tr(${internalKey},${tapLeaf})`,
      taprootSpendPath: 'script',
      tapLeaf
    });

    const satisfaction = output.getTapScriptSatisfaction([
      {
        pubkey: signerA.publicKey.slice(1, 33),
        signature: new Uint8Array(64).fill(2)
      }
    ]);

    const hasOneSelector = satisfaction.stackItems.some(
      (item: Uint8Array) => compare(item, Uint8Array.from([1])) === 0
    );
    expect(hasOneSelector).toBe(true);
  });

  test('throws when miniscript selector is ambiguous', () => {
    const { expand } = DescriptorsFactory(ecc);
    const duplicateDescriptor = `tr(${INTERNAL_KEY},{pk(${LEAF_KEY}),pk(${LEAF_KEY})})`;
    const { tapTreeInfo } = expand({ descriptor: duplicateDescriptor });
    if (!tapTreeInfo) throw new Error('tapTreeInfo not available');
    const signatures = [
      {
        pubkey: fromHex(LEAF_KEY),
        signature: new Uint8Array(64).fill(2)
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
