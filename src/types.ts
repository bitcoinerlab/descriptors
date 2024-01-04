// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { ECPairInterface } from 'ecpair';
import type { BIP32Interface } from 'bip32';
import type { Payment, Network } from 'bitcoinjs-lib';

/**
 * Preimage
 * @alias Preimage
 * @memberof Descriptor
 */
export type Preimage = {
  /**
   * Use same string expressions as in miniscript. For example: "sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)" or "ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e)"
   *
   * Accepted functions: sha256, hash256, ripemd160, hash160
   *
   * Digests must be: 64-character HEX for sha256, hash160 or 30-character HEX for ripemd160 or hash160.
   */
  digest: string;
  /**
   * Hex encoded preimage. Preimages are always 32 bytes (so, 64 character in hex).
   */
  preimage: string;
};
export type TimeConstraints = {
  nLockTime: number | undefined;
  nSequence: number | undefined;
};

/**
 * See {@link _Internal_.ParseKeyExpression | ParseKeyExpression}.
 */
export type KeyInfo = {
  keyExpression: string;
  pubkey?: Buffer; //Must be set unless this corresponds to a ranged-descriptor
  ecpair?: ECPairInterface;
  bip32?: BIP32Interface;
  masterFingerprint?: Buffer;
  originPath?: string; //The path from the masterFingerprint to the xpub/xprv root
  keyPath?: string; //The path from the xpub/xprv root
  path?: string; //The complete path from the master. Format is: "m/val/val/...", starting with an m/, and where val are integers or integers followed by a tilde ', for the hardened case
};

/**
 * An `ExpansionMap` contains destructured information of a descritptor expression.
 *
 * For example, this descriptor `sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))` has the following
 * `expandedExpression`: `sh(wsh(andor(pk(@0),older(8640),pk(@1))))`
 *
 * `key`'s are set using this format: `@i`, where `i` is an integer starting from `0` assigned by parsing and retrieving keys from the descriptor from left to right.
 *
 * For the given example, the `ExpansionMap` is:
 *
 * ```javascript
 *  {
 *    '@0': {
 *      keyExpression:
 *      '0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2'
 *    },
 *    '@1': {
 *      keyExpression:
 *        "[d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*",
 *      keyPath: '/1/2/3/4/*',
 *      originPath: "/49'/0'/0'",
 *      path: "m/49'/0'/0'/1/2/3/4/*",
 *      // Other relevant properties of the type `KeyInfo`: `pubkey`, `ecpair` & `bip32` interfaces, `masterFingerprint`, etc.
 *    }
 *  }
 *```
 *
 *
 */
export type ExpansionMap = {
  //key will have this format: @i, where i is an integer
  [key: string]: KeyInfo;
};

/** @ignore */
interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

/** @ignore */
export interface TinySecp256k1Interface {
  isPoint(p: Uint8Array): boolean;
  pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array;
  isPrivate(d: Uint8Array): boolean;
  pointFromScalar(d: Uint8Array, compressed?: boolean): Uint8Array | null;
  pointAddScalar(
    p: Uint8Array,
    tweak: Uint8Array,
    compressed?: boolean
  ): Uint8Array | null;
  privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
  sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
  signSchnorr?(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array;
  verify(
    h: Uint8Array,
    Q: Uint8Array,
    signature: Uint8Array,
    strict?: boolean
  ): boolean;
  verifySchnorr?(h: Uint8Array, Q: Uint8Array, signature: Uint8Array): boolean;
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array
  ): XOnlyPointAddTweakResult | null;
  isXOnlyPoint(p: Uint8Array): boolean;
  privateNegate(d: Uint8Array): Uint8Array;
}

/**
 * `DescriptorsFactory` creates and returns the {@link DescriptorsFactory | `expand()`}
 * function that parses a descriptor expression and destructures it
 * into its elemental parts. `Expansion` is the type that `expand()` returns.
 */
export type Expansion = {
  /**
   * The corresponding [bitcoinjs-lib Payment](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/payments/index.ts) for the provided expression, if applicable.
   */
  payment?: Payment;

  /**
   * The expanded descriptor expression.
   * See {@link ExpansionMap ExpansionMap} for a detailed explanation.
   */
  expandedExpression?: string;

  /**
   * The extracted miniscript from the expression, if any.
   */
  miniscript?: string;

  /**
   * A map of key expressions in the descriptor to their corresponding expanded keys.
   * See {@link ExpansionMap ExpansionMap} for a detailed explanation.
   */
  expansionMap?: ExpansionMap;

  /**
   * A boolean indicating whether the descriptor uses SegWit.
   */
  isSegwit?: boolean;

  /**
   * The expanded miniscript, if any.
   * It corresponds to the `expandedExpression` without the top-level script
   * expression.
   */
  expandedMiniscript?: string;

  /**
   * The redeem script for the descriptor, if applicable.
   */
  redeemScript?: Buffer;

  /**
   * The witness script for the descriptor, if applicable.
   */
  witnessScript?: Buffer;

  /**
   * Whether the descriptor is a ranged-descriptor.
   */
  isRanged: boolean;

  /**
   * This is the preferred or authoritative representation of an output
   * descriptor expression.
   * It removes the checksum and, if it is a ranged-descriptor, it
   * particularizes it to its index.
   */
  canonicalExpression: string;
};

/**
 * The {@link DescriptorsFactory | `DescriptorsFactory`} function creates and
 * returns the `parseKeyExpression` function, which is an implementation of this
 * interface.
 *
 * It parses and destructures a key expression string (xpub, xprv, pubkey or
 * wif) into {@link KeyInfo | `KeyInfo`}.
 *
 * For example, given this `keyExpression`: `[d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*`, this is the parsed result:
 *
 * ```javascript
 *  {
 *    keyExpression:
 *      "[d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*",
 *    keyPath: '/1/2/3/4/*',
 *    originPath: "/49'/0'/0'",
 *    path: "m/49'/0'/0'/1/2/3/4/*",
 *    // Other relevant properties of the type `KeyInfo`: `pubkey`, `ecpair` & `bip32` interfaces, `masterFingerprint`, etc.
 *  }
 * ```
 *
 * See {@link KeyInfo} for the complete list of elements retrieved by this function.
 */
export interface ParseKeyExpression {
  (params: {
    keyExpression: string;
    /**
     * Indicates if this key expression belongs to a a SegWit output. When set,
     * further checks are done to ensure the public key (if present in the
     * expression) is compressed (33 bytes).
     */
    isSegwit?: boolean;
    network?: Network;
  }): KeyInfo;
}
