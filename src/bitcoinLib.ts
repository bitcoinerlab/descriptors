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

import type { ECPairAPI, ECPairInterface } from 'ecpair';
import type { BIP32API, BIP32Interface } from 'bip32';
import type { Network } from './networks';
import type {
  PsbtInput,
  Bip32Derivation,
  TapBip32Derivation,
  TapLeafScript,
  PartialSig
} from 'bip174';

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

export interface PsbtLikeInput extends Partial<PsbtInput> {
  hash: string | Uint8Array;
  index: number;
  sequence?: number;
}

export type PsbtLikeInputUpdate = Partial<PsbtInput>;

export interface Psbt {
  addInput(input: PsbtLikeInput): void;
  addOutput(output: { script: Uint8Array; value: bigint }): void;
  readonly inputCount: number;
  readonly data: {
    inputs: PsbtInput[];
  };
  readonly txInputs: PsbtTxInput[];
  setLocktime(locktime: number): void;
  readonly locktime: number;
  signInput(index: number, signer: ECPairInterface): void;
  signAllInputs(signer: ECPairInterface): void;
  signInputHD(index: number, hdSigner: BIP32Interface): void;
  signAllInputsHD(hdSigner: BIP32Interface): void;
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

  // ── PSBT factory ──
  Psbt: {
    new (opts?: { network?: Network }): Psbt;
  };

  // ── Key factories ──
  ECPair: ECPairAPI;
  BIP32: BIP32API;

  // ── Raw ECC interface (needed for signature validation: verifySchnorr) ──
  ecc: import('./types').TinySecp256k1Interface;

  // ── ECC initialization (bitcoinjs needs it; scure is a no-op) ──
  initEccLib(): void;
}

// Re-export key types so modules can import from one place
export type {
  ECPairAPI,
  ECPairInterface,
  BIP32API,
  BIP32Interface,
  PsbtInput,
  Bip32Derivation,
  TapBip32Derivation,
  TapLeafScript,
  PartialSig
};
export type { Network } from './networks';
