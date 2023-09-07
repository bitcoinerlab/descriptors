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
   * Use same expressions as in miniscript. For example: "sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)" or "ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e)"
   * Accepted functions: sha256, hash256, ripemd160, hash160
   * Digests must be: 64-character HEX for sha256, hash160 or 30-character HEX for ripemd160 or hash160.
   */
  digest: string;
  /**
   * Hex encoded preimate. Preimages are always 32 bytes (so, 64 character in hex).
   */
  preimage: string;
};
export type TimeConstraints = {
  nLockTime: number | undefined;
  nSequence: number | undefined;
};

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
  privateNegate(d: Uint8Array): Uint8Array;
}

/**
 * The {@link DescriptorsFactory | `DescriptorsFactory`} function creates and returns an implementation of the `Expand` interface.
 * This returned implementation is tailored for the provided `TinySecp256k1Interface`.
 */
export interface Expand {
  (params: {
    /**
     * The descriptor expression to be expanded.
     */
    expression: string;

    /**
     * The descriptor index, if ranged.
     */
    index?: number;

    /**
     * A flag indicating whether the descriptor is required to include a checksum.
     * @defaultValue false
     */
    checksumRequired?: boolean;

    /**
     * The Bitcoin network to use.
     * @defaultValue `networks.bitcoin`
     */
    network?: Network;

    /**
     * Flag to allow miniscript in P2SH.
     * @defaultValue false
     */
    allowMiniscriptInP2SH?: boolean;
  }): {
    /**
     * The corresponding [bitcoinjs-lib Payment](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/payments/index.ts) for the provided expression, if applicable.
     */
    payment?: Payment;

    /**
     * The expanded descriptor expression.
     */
    expandedExpression?: string;

    /**
     * The extracted miniscript from the expression, if any.
     */
    miniscript?: string;

    /**
     * A map of key expressions in the descriptor to their corresponding expanded keys.
     */
    expansionMap?: ExpansionMap;

    /**
     * A boolean indicating whether the descriptor represents a SegWit script.
     */
    isSegwit?: boolean;

    /**
     * The expanded miniscript, if any.
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
     * Whether this expression represents a ranged-descriptor.
     */
    isRanged: boolean;

    /**
     * This is the preferred or authoritative representation of the descriptor expression.
     */
    canonicalExpression: string;
  };
}

/**
 * The {@link DescriptorsFactory | `DescriptorsFactory`} function creates and returns an implementation of the `ParseKeyExpression` interface.
 * This returned implementation is tailored for the provided `TinySecp256k1Interface`.
 */
export interface ParseKeyExpression {
  (params: {
    keyExpression: string;
    /**
     * Indicates if this is a SegWit key expression. When set, further checks
     * ensure the public key (if present in the expression) is compressed
     * (33 bytes).
     */
    isSegwit?: boolean;
    network?: Network;
  }): KeyInfo;
}
