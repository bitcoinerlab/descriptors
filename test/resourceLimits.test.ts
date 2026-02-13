// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { toHex } from 'uint8array-tools';
import { DescriptorsFactory } from '../dist/descriptors';
import { parseTapTreeExpression } from '../dist/tapTree';

const { Output, ECPair } = DescriptorsFactory(ecc);

// Use deterministic, distinct private keys across this file to avoid duplicate
// pubkeys in multisig/taproot tests. `fill(seed)` repeats the byte `seed`
// 32 times, giving us reproducible test-only private keys.
let seedBase = 1;
function nextSigner() {
  const seed = seedBase;
  seedBase += 1;
  return ECPair.fromPrivateKey(new Uint8Array(32).fill(seed));
}

function buildNestedTapTree({
  leafExpression,
  depth
}: {
  leafExpression: string;
  depth: number;
}): string {
  let tree = leafExpression;
  for (let i = 0; i < depth; i++) tree = `{${leafExpression},${tree}}`;
  return tree;
}

describe('resource limits', () => {
  test('taproot tree depth supports up to 128 and rejects 129', () => {
    const leaf = 'pk(@0)';
    const depth128 = buildNestedTapTree({ leafExpression: leaf, depth: 128 });
    const depth129 = buildNestedTapTree({ leafExpression: leaf, depth: 129 });

    expect(() => parseTapTreeExpression(depth128)).not.toThrow();
    expect(() => parseTapTreeExpression(depth129)).toThrow(
      'taproot tree depth is too large'
    );
  });

  test('Output fails fast for taproot trees deeper than 128', () => {
    const internalSigner = nextSigner();
    const leafSigner = nextSigner();
    const internalKey = toHex(internalSigner.publicKey.slice(1, 33));
    const leafKey = toHex(leafSigner.publicKey.slice(1, 33));
    const tree = buildNestedTapTree({
      leafExpression: `pk(${leafKey})`,
      depth: 129
    });

    expect(
      () => new Output({ descriptor: `tr(${internalKey},${tree})` })
    ).toThrow('taproot tree depth is too large');
  });

  test('wsh miniscript rejects witness stack items over 80 bytes', () => {
    const signer = nextSigner();
    const pubkey = toHex(signer.publicKey);
    const output = new Output({ descriptor: `wsh(pk(${pubkey}))` });

    expect(() =>
      output.getScriptSatisfaction([
        {
          pubkey: signer.publicKey,
          signature: new Uint8Array(81)
        }
      ])
    ).toThrow('witness stack item exceeds standard policy');
  });

  test('sh miniscript rejects scriptSig over 1650 bytes', () => {
    const signers = [nextSigner(), nextSigner(), nextSigner(), nextSigner()];
    const descriptor = `sh(multi(4,${signers
      .map(signer => toHex(signer.publicKey))
      .join(',')}))`;
    const output = new Output({ descriptor });

    expect(() =>
      output.getScriptSatisfaction(
        signers.map(signer => ({
          pubkey: signer.publicKey,
          signature: new Uint8Array(500)
        }))
      )
    ).toThrow('scriptSig is too large');
  });

  test('sh miniscript rejects stack items over 520 bytes', () => {
    const signer = nextSigner();
    const output = new Output({
      descriptor: `sh(pk(${toHex(signer.publicKey)}))`
    });

    expect(() =>
      output.getScriptSatisfaction([
        {
          pubkey: signer.publicKey,
          signature: new Uint8Array(521)
        }
      ])
    ).toThrow('stack item is too large');
  });

  test('taproot script-path rejects stack items over 80 bytes', () => {
    const internalSigner = nextSigner();
    const leafSigner = nextSigner();
    const internalKey = toHex(internalSigner.publicKey.slice(1, 33));
    const leafKey = toHex(leafSigner.publicKey.slice(1, 33));
    const output = new Output({
      descriptor: `tr(${internalKey},pk(${leafKey}))`,
      taprootSpendPath: 'script'
    });

    expect(() =>
      output.getTapScriptSatisfaction([
        {
          pubkey: leafSigner.publicKey.slice(1, 33),
          signature: new Uint8Array(81)
        }
      ])
    ).toThrow('taproot script-path stack item exceeds standard policy');
  });
});
