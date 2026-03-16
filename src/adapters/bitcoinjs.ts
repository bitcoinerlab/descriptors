// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * bitcoinjs-lib adapter for BitcoinLib.
 *
 * Wraps bitcoinjs-lib, ecpair, bip32 and related packages into the
 * BitcoinLib interface.  This is the default backend and should produce
 * identical behaviour to the pre-refactor library.
 */

import {
  address,
  networks,
  payments,
  Network,
  Transaction,
  Psbt,
  initEccLib,
  script
} from 'bitcoinjs-lib';
import { BIP32Factory } from 'bip32';
import type { BIP32API } from 'bip32';
import { ECPairFactory } from 'ecpair';
import type { ECPairAPI } from 'ecpair';
import type { TinySecp256k1Interface } from '../types';
import type {
  BitcoinLib,
  PsbtLike,
  FinalScriptsFunc,
  ParsedTransaction
} from '../bitcoinLib';
import { applyPR2137 } from '../applyPR2137';

// ─── PsbtLike wrapper around bitcoinjs-lib Psbt ──────────────────────

class BitcoinjsPsbtAdapter implements PsbtLike {
  readonly #psbt: Psbt;

  constructor(psbt: Psbt) {
    this.#psbt = psbt;
  }

  get raw(): Psbt {
    return this.#psbt;
  }

  addInput(input: Record<string, unknown>): void {
    this.#psbt.addInput(input as unknown as Parameters<Psbt['addInput']>[0]);
  }

  addOutput(output: { script: Uint8Array; value: bigint }): void {
    this.#psbt.addOutput(output);
  }

  get inputCount(): number {
    return this.#psbt.data.inputs.length;
  }

  getInput(index: number) {
    const input = this.#psbt.data.inputs[index];
    if (!input) throw new Error(`Invalid input index ${index}`);
    return input;
  }

  getTxInput(index: number) {
    const txInput = this.#psbt.txInputs[index];
    if (!txInput) throw new Error(`Invalid txInput index ${index}`);
    return {
      hash: txInput.hash,
      index: txInput.index,
      sequence: txInput.sequence ?? 0xffffffff
    };
  }

  setLocktime(locktime: number): void {
    this.#psbt.setLocktime(locktime);
  }

  get locktime(): number {
    return this.#psbt.locktime;
  }

  signInput(
    index: number,
    signer: { publicKey: Uint8Array; sign(hash: Uint8Array): Uint8Array }
  ): void {
    this.#psbt.signInput(index, signer);
  }

  signAllInputs(signer: {
    publicKey: Uint8Array;
    sign(hash: Uint8Array): Uint8Array;
  }): void {
    this.#psbt.signAllInputs(signer);
  }

  signInputHD(
    index: number,
    hdSigner: {
      publicKey: Uint8Array;
      fingerprint: Uint8Array;
      derivePath(path: string): {
        publicKey: Uint8Array;
        sign(hash: Uint8Array): Uint8Array;
        tweak?(t: Uint8Array): {
          publicKey: Uint8Array;
          sign(hash: Uint8Array): Uint8Array;
        };
      };
    }
  ): void {
    applyPR2137(this.#psbt);
    this.#psbt.signInputHD(
      index,
      hdSigner as Parameters<Psbt['signInputHD']>[1]
    );
  }

  signAllInputsHD(hdSigner: {
    publicKey: Uint8Array;
    fingerprint: Uint8Array;
    derivePath(path: string): {
      publicKey: Uint8Array;
      sign(hash: Uint8Array): Uint8Array;
      tweak?(t: Uint8Array): {
        publicKey: Uint8Array;
        sign(hash: Uint8Array): Uint8Array;
      };
    };
  }): void {
    applyPR2137(this.#psbt);
    this.#psbt.signAllInputsHD(
      hdSigner as Parameters<Psbt['signAllInputsHD']>[0]
    );
  }

  finalizeInput(index: number, finalizer?: FinalScriptsFunc): void {
    this.#psbt.finalizeInput(
      index,
      finalizer as Parameters<Psbt['finalizeInput']>[1]
    );
  }

  finalizeTaprootInput(
    index: number,
    tapLeafHashToFinalize: Uint8Array | undefined,
    finalizer: () => { finalScriptWitness: Uint8Array }
  ): void {
    // finalizeTaprootInput is added by applyPR2137 or exists in newer bitcoinjs
    const psbtAny = this.#psbt as unknown as Record<string, unknown>;
    if (typeof psbtAny['finalizeTaprootInput'] === 'function') {
      (
        psbtAny['finalizeTaprootInput'] as (
          idx: number,
          hash: Uint8Array | undefined,
          fn: () => { finalScriptWitness: Uint8Array }
        ) => void
      )(index, tapLeafHashToFinalize, finalizer);
    } else {
      // Fallback: manually set the finalScriptWitness
      const result = finalizer();
      this.#psbt.updateInput(index, {
        finalScriptWitness: result.finalScriptWitness
      });
      // Clear non-final fields
      const input = this.#psbt.data.inputs[index]!;
      delete input.tapScriptSig;
      delete input.tapLeafScript;
      delete input.tapBip32Derivation;
      delete input.tapInternalKey;
      delete input.tapMerkleRoot;
    }
  }

  validateSignaturesOfInput(
    index: number,
    validator: (
      pubkey: Uint8Array,
      msghash: Uint8Array,
      signature: Uint8Array
    ) => boolean
  ): boolean {
    return this.#psbt.validateSignaturesOfInput(index, validator);
  }

  updateInput(index: number, data: Record<string, unknown>): void {
    this.#psbt.updateInput(index, data as Parameters<Psbt['updateInput']>[1]);
  }

  extractTransaction() {
    const tx = this.#psbt.extractTransaction();
    return {
      toHex: () => tx.toHex(),
      ins: tx.ins.map(i => ({ witness: i.witness }))
    };
  }

  toBase64(): string {
    return this.#psbt.toBase64();
  }
}

// ─── Transaction wrapper ──────────────────────────────────────────────

function wrapTransaction(
  tx: InstanceType<typeof Transaction>
): ParsedTransaction {
  return {
    getId: () => tx.getId(),
    outs: tx.outs.map(o => ({ script: o.script, value: o.value })),
    toBuffer: () => tx.toBuffer()
  };
}

// ─── Factory ──────────────────────────────────────────────────────────

/**
 * Create a BitcoinLib backed by bitcoinjs-lib.
 *
 * @param ecc  A TinySecp256k1Interface (e.g. `@bitcoinerlab/secp256k1`).
 */
export function createBitcoinjsLib(ecc: TinySecp256k1Interface): BitcoinLib {
  initEccLib(ecc);

  const ECPair: ECPairAPI = ECPairFactory(ecc);
  const BIP32: BIP32API = BIP32Factory(ecc);

  return {
    payments,
    script,

    Transaction: {
      fromHex: hex => wrapTransaction(Transaction.fromHex(hex)),
      fromBuffer: buf =>
        wrapTransaction(Transaction.fromBuffer(Buffer.from(buf)))
    },

    address: {
      toOutputScript: (addr, net) =>
        address.toOutputScript(addr, net as Network)
    },

    Psbt: class {
      constructor(opts?: { network?: unknown }) {
        const psbt = new Psbt(opts as ConstructorParameters<typeof Psbt>[0]);
        return new BitcoinjsPsbtAdapter(psbt) as unknown as PsbtLike;
      }
    } as unknown as { new (opts?: { network?: unknown }): PsbtLike },

    ECPair,
    BIP32,

    networks: {
      bitcoin: networks.bitcoin as unknown as import('../bitcoinLib').Network,
      testnet: networks.testnet as unknown as import('../bitcoinLib').Network,
      regtest: networks.regtest as unknown as import('../bitcoinLib').Network
    },

    ecc,

    initEccLib: () => initEccLib(ecc)
  };
}
