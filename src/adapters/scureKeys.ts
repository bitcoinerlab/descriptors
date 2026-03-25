// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import type {
  BIP32InterfaceLike,
  ECPairInterfaceLike,
  ScureHDKeyLike
} from '../bitcoinLib';
import { uint32ToBytesBE } from './scure/common';

const CURVE_N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
);

function mod(a: bigint, n: bigint): bigint {
  const result = a % n;
  return result >= 0n ? result : result + n;
}

function tweakPrivateKey(
  privateKey: Uint8Array,
  tweak: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  if (tweak.length !== 32) throw new Error('Error: invalid tweak value');
  const tweakNum = bytesToNumberBE(tweak);
  if (tweakNum <= 0n || tweakNum >= CURVE_N)
    throw new Error('Error: invalid tweak value');

  let d = bytesToNumberBE(privateKey);
  if (publicKey[0] === 0x03) d = mod(-d, CURVE_N);
  const tweaked = mod(d + tweakNum, CURVE_N);
  if (tweaked === 0n) throw new Error('Error: invalid tweak value');
  return numberToBytesBE(tweaked, 32);
}

export function wrapScurePrivateKey(
  privateKey: Uint8Array,
  compressed = true
): ECPairInterfaceLike {
  if (!secp256k1.utils.isValidSecretKey(privateKey))
    throw new Error('Error: invalid private key');

  const compressedPublicKey = secp256k1.getPublicKey(privateKey, true);
  const publicKey = compressed
    ? compressedPublicKey
    : secp256k1.getPublicKey(privateKey, false);
  const xOnlyPubkey = compressedPublicKey.slice(1, 33);

  return {
    publicKey,
    privateKey,
    sign(hash: Uint8Array): Uint8Array {
      return secp256k1.sign(hash, privateKey, {
        prehash: false,
        lowS: true,
        format: 'compact'
      });
    },
    verify(hash: Uint8Array, signature: Uint8Array): boolean {
      return secp256k1.verify(signature, hash, publicKey, {
        prehash: false,
        lowS: true,
        format: 'compact'
      });
    },
    tweak(t: Uint8Array): ECPairInterfaceLike {
      return wrapScurePrivateKey(
        tweakPrivateKey(privateKey, t, compressedPublicKey),
        compressed
      );
    },
    signSchnorr(hash: Uint8Array): Uint8Array {
      return schnorr.sign(hash, privateKey);
    },
    verifySchnorr(hash: Uint8Array, signature: Uint8Array): boolean {
      return schnorr.verify(signature, hash, xOnlyPubkey);
    }
  };
}

export function wrapScurePublicKey(publicKey: Uint8Array): ECPairInterfaceLike {
  if (!secp256k1.utils.isValidPublicKey(publicKey))
    throw new Error('Error: invalid public key point');

  const compressedPubkey =
    publicKey.length === 33
      ? publicKey
      : secp256k1.Point.fromHex(hex.encode(publicKey)).toBytes(true);
  const xOnlyPubkey = compressedPubkey.slice(1, 33);

  return {
    publicKey,
    sign(): Uint8Array {
      throw new Error('Error: private key is required for signing');
    },
    verify(hash: Uint8Array, signature: Uint8Array): boolean {
      return secp256k1.verify(signature, hash, publicKey, {
        prehash: false,
        lowS: true,
        format: 'compact'
      });
    },
    tweak(): ECPairInterfaceLike {
      throw new Error('Error: private key is required for tweak');
    },
    verifySchnorr(hash: Uint8Array, signature: Uint8Array): boolean {
      return schnorr.verify(signature, hash, xOnlyPubkey);
    }
  };
}

function normalizePath(path: string): string {
  const p = path.replaceAll('H', "'").replaceAll('h', "'");
  if (p === 'm' || p === "m'") return 'm';
  if (p.startsWith('m/')) return p;
  if (p.startsWith('/')) return `m${p}`;
  return `m/${p}`;
}

export function wrapScureHDKey(node: ScureHDKeyLike): BIP32InterfaceLike {
  if (!node.publicKey)
    throw new Error('Error: scure HDKey is missing publicKey for BIP32 usage');

  return {
    publicKey: node.publicKey,
    ...(node.privateKey ? { privateKey: node.privateKey } : {}),
    fingerprint: uint32ToBytesBE(node.fingerprint),
    derive(index: number): BIP32InterfaceLike {
      return wrapScureHDKey(node.deriveChild(index));
    },
    derivePath(path: string): BIP32InterfaceLike {
      return wrapScureHDKey(node.derive(normalizePath(path)));
    },
    neutered(): BIP32InterfaceLike {
      return wrapScureHDKey(
        HDKey.fromExtendedKey(node.publicExtendedKey, node.versions)
      );
    },
    toBase58(): string {
      return node.privateKey ? node.privateExtendedKey : node.publicExtendedKey;
    },
    sign(hash: Uint8Array): Uint8Array {
      if (!node.privateKey)
        throw new Error('Error: cannot sign with neutered ScureHDKeyLike');
      return node.sign(hash);
    },
    tweak(t: Uint8Array): ECPairInterfaceLike {
      if (!node.privateKey)
        throw new Error('Error: cannot tweak a neutered ScureHDKeyLike');
      return wrapScurePrivateKey(node.privateKey).tweak(t);
    }
  };
}
