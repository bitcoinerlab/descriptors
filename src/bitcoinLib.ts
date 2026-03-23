// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * This module defines the BitcoinLib interface – the abstraction boundary
 * between the descriptor library core and the underlying Bitcoin
 * implementation (bitcoinjs-lib, @scure/btc-signer, or any other).
 *
 * Adapters implement this interface. The core library receives it via
 * DescriptorsFactory and threads it through closures.
 */

import type { Network } from './networks';
import type { PsbtInput } from './bip174';

/**
 * Internal signer shape used by this library.
 *
 * In user code, this usually corresponds to a
 * {@link https://github.com/bitcoinjs/ecpair | bitcoinjs `ECPairInterface`}.
 */
export interface ECPairInterfaceLike {
  publicKey: Uint8Array;
  privateKey?: Uint8Array;
  sign(hash: Uint8Array, lowR?: boolean): Uint8Array;
  verify(hash: Uint8Array, signature: Uint8Array): boolean;
  tweak(t: Uint8Array): ECPairInterfaceLike;
  signSchnorr?(hash: Uint8Array): Uint8Array;
  verifySchnorr?(hash: Uint8Array, signature: Uint8Array): boolean;
}

/**
 * Full bitcoinjs ecpair-compatible interface.
 *
 * This is exposed only for factory return typing when the adapter is the
 * native bitcoinjs stack. Internal code should continue using
 * `ECPairInterfaceLike`.
 */
interface ECPairInterface extends ECPairInterfaceLike {
  compressed: boolean;
  network: Network;
  lowR: boolean;
  toWIF(): string;
  signSchnorr(hash: Uint8Array): Uint8Array;
  verifySchnorr(hash: Uint8Array, signature: Uint8Array): boolean;
  tweak(t: Uint8Array): ECPairInterface;
}

/**
 * Internal HD node shape used by this library.
 *
 * In user code, this usually corresponds to a
 * {@link https://github.com/bitcoinjs/bip32 | bitcoinjs `BIP32Interface`}.
 */
export interface BIP32InterfaceLike {
  publicKey: Uint8Array;
  privateKey?: Uint8Array;
  fingerprint: Uint8Array;
  derive(index: number): BIP32InterfaceLike;
  derivePath(path: string): BIP32InterfaceLike;
  neutered(): BIP32InterfaceLike;
  toBase58(): string;
  sign(hash: Uint8Array): Uint8Array;
  tweak(t: Uint8Array): Omit<ECPairInterfaceLike, 'tweak' | 'privateKey'>;
}

/**
 * Full bitcoinjs bip32-compatible interface.
 *
 * This is exposed only for factory return typing when the adapter is the
 * native bitcoinjs stack. Internal code should continue using
 * `BIP32InterfaceLike`.
 */
interface BIP32Interface extends BIP32InterfaceLike {
  chainCode: Uint8Array;
  network: Network;
  depth: number;
  index: number;
  parentFingerprint: number;
  identifier: Uint8Array;
  isNeutered(): boolean;
  neutered(): BIP32Interface;
  derive(index: number): BIP32Interface;
  deriveHardened(index: number): BIP32Interface;
  derivePath(path: string): BIP32Interface;
  toWIF(): string;
  tweak(t: Uint8Array): Omit<ECPairInterface, 'tweak' | 'privateKey'>;
  lowR: boolean;
  verify(hash: Uint8Array, signature: Uint8Array): boolean;
  signSchnorr(hash: Uint8Array): Uint8Array;
  verifySchnorr(hash: Uint8Array, signature: Uint8Array): boolean;
}

/**
 * Structural subset of
 * {@link https://github.com/paulmillr/scure-bip32 | `@scure/bip32` `HDKey`}.
 */
export interface ScureHDKeyLike {
  publicKey: Uint8Array | null;
  privateKey: Uint8Array | null;
  fingerprint: number;
  versions?: { public: number; private: number };
  derive(path: string): ScureHDKeyLike;
  deriveChild(index: number): ScureHDKeyLike;
  sign(hash: Uint8Array): Uint8Array;
  publicExtendedKey: string;
  privateExtendedKey: string;
}

/**
 * Internal key-factory shape used by this library.
 *
 * In user code, this usually corresponds to
 * {@link https://github.com/bitcoinjs/ecpair | `ECPairFactory` output}.
 */
export interface ECPairAPILike {
  isPoint(maybePoint: unknown): boolean;
  fromPublicKey(
    buffer: Uint8Array,
    options?: { compressed?: boolean; network?: Network }
  ): ECPairInterfaceLike;
  fromWIF(
    wifString: string,
    network?: Network | Network[]
  ): ECPairInterfaceLike;
}

/** Full bitcoinjs ecpair-compatible API. */
export interface ECPairAPI {
  isPoint(maybePoint: unknown): boolean;
  fromPrivateKey(
    buffer: Uint8Array,
    options?: { compressed?: boolean; network?: Network }
  ): ECPairInterface;
  fromPublicKey(
    buffer: Uint8Array,
    options?: { compressed?: boolean; network?: Network }
  ): ECPairInterface;
  makeRandom(options?: {
    compressed?: boolean;
    network?: Network;
    rng?: (arg?: number) => Uint8Array;
  }): ECPairInterface;
  fromWIF(wifString: string, network?: Network | Network[]): ECPairInterface;
}

/**
 * Internal HD-factory shape used by this library.
 *
 * In user code, this usually corresponds to
 * {@link https://github.com/bitcoinjs/bip32 | `BIP32Factory` output}.
 */
export interface BIP32APILike {
  fromBase58(inString: string, network?: Network): BIP32InterfaceLike;
}

/** Full bitcoinjs bip32-compatible API. */
export interface BIP32API {
  fromSeed(seed: Uint8Array, network?: Network): BIP32Interface;
  fromBase58(inString: string, network?: Network): BIP32Interface;
  fromPublicKey(
    publicKey: Uint8Array,
    chainCode: Uint8Array,
    network?: Network
  ): BIP32Interface;
  fromPrivateKey(
    privateKey: Uint8Array,
    chainCode: Uint8Array,
    network?: Network
  ): BIP32Interface;
}

// ─── Payment ─────────────────────────────────────────────────────────

export interface Payment {
  output?: Uint8Array;
  address?: string;
  input?: Uint8Array;
  witness?: Uint8Array[];
  redeem?: Payment;
  hash?: Uint8Array;
  pubkey?: Uint8Array;
  /** Taproot x-only internal pubkey (32 bytes). */
  internalPubkey?: Uint8Array;
  network?: Network;
}

// ─── Psbt ────────────────────────────────────────────────────────────

/**
 * Minimal PSBT interface consumed by this library.
 *
 * This is intentionally a bitcoinjs-compatible structural subset so raw
 * `bitcoinjs-lib.Psbt` instances can be passed directly to public APIs.
 * The scure adapter maps `@scure/btc-signer.Transaction` to this surface.
 */
export interface PsbtTxInput {
  hash: Uint8Array;
  index: number;
  sequence?: number;
}

export type PsbtLikeInputUpdate = Partial<PsbtInput>;

/**
 * Minimal interface compatible with bitcoinjs-lib Psbt.
 *
 * This is an internal structural type. User code can pass concrete
 * {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/psbt.ts | bitcoinjs-lib `Psbt`}.
 */
export interface PsbtLike {
  addInput(input: PsbtInput): void;
  addOutput(output: { script: Uint8Array; value: bigint }): void;
  readonly inputCount: number;
  readonly data: { inputs: PsbtInput[] };
  readonly txInputs: PsbtTxInput[];
  setLocktime(locktime: number): void;
  readonly locktime: number;
  signInput(index: number, signer: ECPairInterfaceLike): void;
  signAllInputs(signer: ECPairInterfaceLike): void;
  signInputHD(index: number, hdSigner: BIP32InterfaceLike): void;
  signAllInputsHD(hdSigner: BIP32InterfaceLike): void;
  finalizeInput(index: number, finalizer?: FinalScriptsFunc): void;
  finalizeTaprootInput(
    index: number,
    tapLeafHashToFinalize: Uint8Array | undefined,
    finalizer: () => { finalScriptWitness: Uint8Array }
  ): void;
  validateSignaturesOfInput(
    index: number,
    validator: (
      pubkey: Uint8Array,
      msghash: Uint8Array,
      signature: Uint8Array
    ) => boolean
  ): boolean;
  updateInput(index: number, data: PsbtLikeInputUpdate): void;
  toBase64(): string;
}

export type FinalScriptsFunc = (
  inputIndex: number,
  input: PsbtInput,
  script: Uint8Array,
  isSegwit: boolean,
  isP2SH: boolean,
  isP2WSH: boolean
) => {
  finalScriptSig: Uint8Array | undefined;
  finalScriptWitness: Uint8Array | undefined;
};

/**
 * Minimal interface compatible with @scure/btc-signer Transaction.
 *
 * This is an internal structural type. User code can pass concrete
 * {@link https://github.com/paulmillr/scure-btc-signer | `@scure/btc-signer` `Transaction`}.
 */
export interface ScureTransactionLike {
  inputsLength: number;
  outputsLength: number;
  getInput(index: number): unknown;
  getOutput(index: number): unknown;
  addInput(input: unknown): void;
  addOutput(output: { script: Uint8Array; amount: bigint }): void;
  sign(signer: unknown): number;
  signIdx(signer: unknown, index: number): boolean;
  finalize(): void;
  finalizeIdx(index: number): void;
  toPSBT(): Uint8Array;
  lockTime: number;
}

/**
 * Type guard to detect if a transaction object is a
 * `@scure/btc-signer` `Transaction`.
 * Checks for scure-specific properties that distinguish it from bitcoinjs-lib Psbt.
 */
export function isScureTransaction(
  psbt: PsbtLike | ScureTransactionLike
): psbt is ScureTransactionLike {
  const candidate = psbt as ScureTransactionLike;
  return (
    'inputsLength' in candidate &&
    'outputsLength' in candidate &&
    'toPSBT' in candidate &&
    typeof candidate.toPSBT === 'function' &&
    'lockTime' in candidate
  );
}

// ─── Transaction ─────────────────────────────────────────────────────

export interface Transaction {
  getId(): string;
  outs: Array<{ script: Uint8Array; value: bigint }>;
  toBuffer(): Uint8Array;
}

// ─── Taptree (for p2tr) ──────────────────────────────────────────────

export type Tapleaf = { output: Uint8Array; version?: number };
export type Taptree = [Taptree | Tapleaf, Taptree | Tapleaf] | Tapleaf;

// ─── BitcoinLib ──────────────────────────────────────────────────────

/**
 * The complete Bitcoin backend adapter.
 *
 * Implementations wrap either bitcoinjs-lib or @scure/btc-signer.
 * Received by `DescriptorsFactory` and threaded through the library.
 */
export interface BitcoinLib {
  // ── Payments ──
  payments: {
    p2pk(a: { pubkey: Uint8Array; network?: Network }): Payment;
    p2pkh(a: {
      pubkey?: Uint8Array;
      hash?: Uint8Array;
      output?: Uint8Array;
      network?: Network;
    }): Payment;
    p2sh(a: {
      redeem?: Payment;
      output?: Uint8Array;
      network?: Network;
    }): Payment;
    p2wpkh(a: {
      pubkey?: Uint8Array;
      hash?: Uint8Array;
      output?: Uint8Array;
      network?: Network;
    }): Payment;
    p2wsh(a: {
      redeem?: Payment;
      output?: Uint8Array;
      network?: Network;
    }): Payment;
    p2ms(a: { m: number; pubkeys: Uint8Array[]; network?: Network }): Payment;
    p2tr(a: {
      internalPubkey?: Uint8Array;
      scriptTree?: Taptree;
      redeem?: { output: Uint8Array; redeemVersion?: number };
      output?: Uint8Array;
      network?: Network;
    }): Payment;
  };

  // ── Script ──
  script: {
    fromASM(asm: string): Uint8Array;
    toStack(scriptBuf: Uint8Array): Uint8Array[];
    decompile(scriptBuf: Uint8Array): Array<number | Uint8Array> | null;
    countNonPushOnlyOPs(chunks: Array<number | Uint8Array>): number;
    number: {
      encode(n: number): Uint8Array;
    };
  };

  // ── Transaction parsing ──
  Transaction: {
    fromHex(hex: string): Transaction;
    fromBuffer(buf: Uint8Array): Transaction;
  };

  // ── Address ──
  address: {
    toOutputScript(addr: string, network?: Network): Uint8Array;
  };

  // ── Key factories ──
  ECPair: ECPairAPILike;
  BIP32: BIP32APILike;

  // ── Signature validation ──
  verifySchnorr(
    msghash: Uint8Array,
    pubkey: Uint8Array,
    signature: Uint8Array
  ): boolean;
}
