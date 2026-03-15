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
import type {
  PsbtInput,
  Bip32Derivation,
  TapBip32Derivation,
  TapLeafScript,
  PartialSig
} from 'bip174';

// ─── Network ─────────────────────────────────────────────────────────

export interface Network {
  messagePrefix: string;
  bech32: string;
  bip32: { public: number; private: number };
  pubKeyHash: number;
  scriptHash: number;
  wif: number;
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
 * bitcoinjs adapter: thin wrapper around `bitcoinjs-lib.Psbt`.
 * scure adapter:     wrapper around `@scure/btc-signer.Transaction`.
 */
export interface PsbtLike {
  // ── Input/Output management ──
  addInput(input: Record<string, unknown>): void;
  addOutput(output: { script: Uint8Array; value: bigint }): void;

  // ── Reading inputs ──
  readonly inputCount: number;
  getInput(index: number): PsbtInput;
  /** Transaction-level input data (hash, index, sequence). */
  getTxInput(index: number): {
    hash: Uint8Array;
    index: number;
    sequence: number;
  };

  // ── Locktime ──
  setLocktime(locktime: number): void;
  readonly locktime: number;

  // ── Signing ──
  signInput(index: number, signer: ECPairInterface): void;
  signAllInputs(signer: ECPairInterface): void;
  signInputHD(index: number, hdSigner: BIP32Interface): void;
  signAllInputsHD(hdSigner: BIP32Interface): void;

  // ── Finalization ──
  finalizeInput(index: number, finalizer?: FinalScriptsFunc): void;
  finalizeTaprootInput(
    index: number,
    tapLeafHashToFinalize: Uint8Array | undefined,
    finalizer: () => { finalScriptWitness: Uint8Array }
  ): void;

  // ── Validation ──
  validateSignaturesOfInput(
    index: number,
    validator: (
      pubkey: Uint8Array,
      msghash: Uint8Array,
      signature: Uint8Array
    ) => boolean
  ): boolean;

  // ── Update ──
  updateInput(index: number, data: Record<string, unknown>): void;

  // ── Serialization ──
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

// ─── Parsed Transaction ──────────────────────────────────────────────

export interface ParsedTransaction {
  getId(): string;
  outs: Array<{ script: Uint8Array; value: bigint }>;
  toBuffer(): Uint8Array;
}

// ─── Taptree (for p2tr) ──────────────────────────────────────────────

type BitcoinJsTapleaf = { output: Uint8Array; version?: number };
export type Taptree =
  | [Taptree | BitcoinJsTapleaf, Taptree | BitcoinJsTapleaf]
  | BitcoinJsTapleaf;

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
    p2ms(a: {
      m: number;
      pubkeys: Uint8Array[];
      network?: Network;
    }): Payment;
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
    decompile(
      scriptBuf: Uint8Array
    ): Array<number | Uint8Array> | null;
    countNonPushOnlyOPs(
      chunks: Array<number | Uint8Array>
    ): number;
    number: {
      encode(n: number): Uint8Array;
    };
  };

  // ── Crypto ──
  crypto: {
    hash160(data: Uint8Array): Uint8Array;
    sha256(data: Uint8Array): Uint8Array;
    taggedHash(tag: string, data: Uint8Array): Uint8Array;
  };

  // ── Transaction parsing ──
  Transaction: {
    fromHex(hex: string): ParsedTransaction;
    fromBuffer(buf: Uint8Array): ParsedTransaction;
  };

  // ── Address ──
  address: {
    toOutputScript(addr: string, network?: Network): Uint8Array;
  };

  // ── PSBT factory ──
  Psbt: {
    new (opts?: { network?: Network }): PsbtLike;
  };

  // ── Key factories ──
  ECPair: ECPairAPI;
  BIP32: BIP32API;

  // ── Networks ──
  networks: {
    bitcoin: Network;
    testnet: Network;
    regtest: Network;
  };

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
