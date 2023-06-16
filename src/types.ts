// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { ECPairInterface } from 'ecpair';
import type { BIP32Interface } from 'bip32';
import type { Network, Payment, Psbt } from 'bitcoinjs-lib';
import type { PartialSig } from 'bip174/src/lib/interfaces';

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

export interface ParseKeyExpression {
  (params: {
    keyExpression: string;
    isSegwit?: boolean;
    network?: Network;
  }): KeyInfo;
}

export interface Expand {
  (params: {
    expression: string;
    loggedExpression?: string;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): {
    payment?: Payment;
    expandedExpression?: string;
    miniscript?: string;
    expansionMap?: ExpansionMap;
    isSegwit?: boolean;
    expandedMiniscript?: string;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
  };
}

interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

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

//https://stackoverflow.com/questions/65220834/what-return-type-should-i-define-for-a-function-that-returns-a-class
/**
 * DescriptorInfo
 * What defines a Descriptor. This is the type needed in the constructor.
 * @alias DescriptorInfo
 * @memberof Descriptor
 */
export type DescriptorInfo = {
  expression: string;
  index?: number;
  checksumRequired?: boolean;
  allowMiniscriptInP2SH?: boolean;
  network?: Network;
  preimages?: Preimage[];
  signersPubKeys?: Buffer[];
};

export interface DescriptorInterface {
  getPayment(): Payment;
  getAddress(): string;
  getScriptPubKey(): Buffer;
  getScriptSatisfaction(signatures: PartialSig[]): Buffer;
  getSequence(): number | undefined;
  getLockTime(): number | undefined;
  getWitnessScript(): Buffer | undefined;
  getRedeemScript(): Buffer | undefined;
  getNetwork(): Network;
  isSegwit(): boolean | undefined;
  updatePsbt({
    psbt,
    vout,
    txHex,
    txId,
    value
  }: {
    psbt: Psbt;
    vout: number;
    txHex?: string;
    txId?: string;
    value?: number;
  }): number;
  finalizePsbtInput({
    index,
    psbt,
    validate = true
  }: {
    index: number;
    psbt: Psbt;
    validate?: boolean | undefined;
  }): void;
  expand(): {
    expandedExpression?: string;
    miniscript?: string;
    expandedMiniscript?: string;
    expansionMap?: ExpansionMap;
  };
}

export interface DescriptorInterfaceConstructor {
  new (args: DescriptorInfo): DescriptorInterface;
}
