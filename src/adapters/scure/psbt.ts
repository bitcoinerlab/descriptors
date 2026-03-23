// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
import { base64 } from '@scure/base';
import { RawTx, RawWitness } from '@scure/btc-signer/script.js';
import type {
  TransactionInput as ScureTransactionInput,
  TransactionInputUpdate as ScureTransactionInputUpdate
} from '@scure/btc-signer/psbt.js';
import type {
  BIP32InterfaceLike,
  FinalScriptsFunc,
  PsbtLike,
  PsbtLikeInputUpdate,
  PsbtTxInput
} from '../../bitcoinLib';
import type { PsbtInput } from '../../bip174';
import { concat } from 'uint8array-tools';
import { uint32FromBytesBE, uint32ToBytesBE } from './common';

interface SignerWithPrivateKey {
  publicKey: Uint8Array;
  sign(hash: Uint8Array): Uint8Array;
  privateKey?: Uint8Array;
}

interface DerivableHdSigner {
  publicKey: Uint8Array;
  sign(hash: Uint8Array): Uint8Array;
  derivePath(path: string): DerivableHdSigner;
  derive(index: number): DerivableHdSigner;
  fingerprint: Uint8Array | number;
  privateKey?: Uint8Array;
}

let warnedAboutScureSignatureValidation = false;

function copyDefinedFields(
  source: Record<string, unknown>,
  target: Record<string, unknown>,
  keys: readonly string[]
) {
  for (const key of keys) {
    const value = source[key];
    if (value !== undefined) target[key] = source[key];
  }
}

function pathArrayToString(path: number[]) {
  if (path.length === 0) return 'm';
  const parts = path.map(idx => {
    if (idx >= 0x80000000) return `${idx - 0x80000000}'`;
    return `${idx}`;
  });
  return `m/${parts.join('/')}`;
}

function toScureInputUpdate(input: PsbtLikeInputUpdate) {
  const result: ScureTransactionInputUpdate = {};

  copyDefinedFields(input, result, [
    'nonWitnessUtxo',
    'redeemScript',
    'witnessScript',
    'tapInternalKey',
    'tapMerkleRoot',
    'tapKeySig',
    'sighashType',
    'finalScriptSig'
  ]);

  if (input.witnessUtxo)
    result.witnessUtxo = {
      script: input.witnessUtxo.script,
      amount: input.witnessUtxo.value
    };

  if (input.bip32Derivation)
    result.bip32Derivation = input.bip32Derivation.map(
      ({ pubkey, masterFingerprint, path }) => [
        pubkey,
        {
          fingerprint: uint32FromBytesBE(masterFingerprint),
          path: btc.bip32Path(path)
        }
      ]
    );

  if (input.tapBip32Derivation)
    result.tapBip32Derivation = input.tapBip32Derivation.map(
      ({ pubkey, masterFingerprint, path, leafHashes }) => [
        pubkey,
        {
          hashes: leafHashes,
          der: {
            fingerprint: uint32FromBytesBE(masterFingerprint),
            path: btc.bip32Path(path)
          }
        }
      ]
    );

  if (input.partialSig)
    result.partialSig = input.partialSig.map(({ pubkey, signature }) => [
      pubkey,
      signature
    ]);

  if (input.tapLeafScript)
    result.tapLeafScript = input.tapLeafScript.map(leaf => {
      const decoded = btc.TaprootControlBlock.decode(leaf.controlBlock);
      const controlBlock = {
        ...decoded,
        version: (decoded.version & 1) | leaf.leafVersion
      };
      return [
        controlBlock,
        concat([leaf.script, Uint8Array.from([leaf.leafVersion])])
      ];
    });

  if (input.tapScriptSig)
    result.tapScriptSig = input.tapScriptSig.map(sig => [
      { pubKey: sig.pubkey, leafHash: sig.leafHash },
      sig.signature
    ]);

  if (input.finalScriptWitness)
    result.finalScriptWitness = RawWitness.decode(input.finalScriptWitness);

  return result;
}

function scureInputToBitcoinjs(raw: ScureTransactionInput) {
  const input: Partial<PsbtInput> = {};

  copyDefinedFields(raw, input, [
    'redeemScript',
    'witnessScript',
    'tapInternalKey',
    'tapMerkleRoot',
    'tapKeySig',
    'sighashType',
    'finalScriptSig'
  ]);

  if (raw.nonWitnessUtxo)
    input.nonWitnessUtxo = RawTx.encode(raw.nonWitnessUtxo);
  if (raw.witnessUtxo)
    input.witnessUtxo = {
      script: raw.witnessUtxo.script,
      value: raw.witnessUtxo.amount
    };

  if (raw.bip32Derivation)
    input.bip32Derivation = raw.bip32Derivation.map(
      ([pubkey, { fingerprint, path }]) => ({
        pubkey,
        masterFingerprint: uint32ToBytesBE(fingerprint),
        path: pathArrayToString(path)
      })
    );

  if (raw.tapBip32Derivation)
    input.tapBip32Derivation = raw.tapBip32Derivation.map(
      ([pubkey, { hashes, der }]) => ({
        pubkey,
        masterFingerprint: uint32ToBytesBE(der.fingerprint),
        path: pathArrayToString(der.path),
        leafHashes: hashes
      })
    );

  if (raw.partialSig)
    input.partialSig = raw.partialSig.map(([pubkey, signature]) => ({
      pubkey,
      signature
    }));

  if (raw.tapLeafScript)
    input.tapLeafScript = raw.tapLeafScript.map(
      ([controlBlock, scriptWithVersion]) => ({
        controlBlock: btc.TaprootControlBlock.encode(controlBlock),
        script: scriptWithVersion.subarray(0, -1),
        leafVersion: scriptWithVersion[scriptWithVersion.length - 1] ?? 0xc0
      })
    );

  if (raw.tapScriptSig)
    input.tapScriptSig = raw.tapScriptSig.map(([key, signature]) => ({
      pubkey: key.pubKey,
      leafHash: key.leafHash,
      signature
    }));

  if (raw.finalScriptWitness)
    input.finalScriptWitness = RawWitness.encode(raw.finalScriptWitness);

  return input;
}

function requirePrivateKey(signer: SignerWithPrivateKey) {
  if (!signer.privateKey)
    throw new Error('Error: signer must expose a privateKey for scure signing');
  return signer.privateKey;
}

function toScureHDKey(hdSigner: DerivableHdSigner) {
  if (!hdSigner.privateKey)
    throw new Error(
      'Error: HD signer must expose a privateKey for scure signing'
    );
  return {
    publicKey: hdSigner.publicKey,
    privateKey: hdSigner.privateKey,
    fingerprint:
      hdSigner.fingerprint instanceof Uint8Array
        ? uint32FromBytesBE(hdSigner.fingerprint)
        : hdSigner.fingerprint,
    derive(path: string) {
      return toScureHDKey(hdSigner.derivePath(path));
    },
    deriveChild(index: number) {
      return toScureHDKey(hdSigner.derive(index));
    },
    sign: hdSigner.sign.bind(hdSigner)
  };
}

class ScurePsbtAdapter implements PsbtLike {
  readonly #tx: btc.Transaction;

  constructor(tx: btc.Transaction) {
    this.#tx = tx;
  }

  get raw() {
    return this.#tx;
  }

  addInput(input: PsbtInput & Partial<PsbtTxInput>) {
    if (!input.hash) throw new Error('PSBT input hash is required');
    if (input.index === undefined)
      throw new Error('PSBT input index is required');

    const scureInput = toScureInputUpdate(input);
    // bitcoinjs stores input hash little-endian; scure expects txid order.
    scureInput.txid = Uint8Array.from(input.hash).reverse();
    scureInput.index = input.index;
    if (input.sequence !== undefined) scureInput.sequence = input.sequence;

    this.#tx.addInput(scureInput);
  }

  addOutput(output: { script: Uint8Array; value: bigint }) {
    this.#tx.addOutput({ script: output.script, amount: output.value });
  }

  get inputCount() {
    return this.#tx.inputsLength;
  }

  get data() {
    return {
      inputs: Array.from({ length: this.#tx.inputsLength }, (_value, index) =>
        scureInputToBitcoinjs(this.#tx.getInput(index))
      )
    };
  }

  get txInputs() {
    return Array.from({ length: this.#tx.inputsLength }, (_value, index) => {
      const raw = this.#tx.getInput(index);
      if (!raw.txid) throw new Error(`PSBT input ${index} missing txid`);
      if (raw.index === undefined)
        throw new Error(`PSBT input ${index} missing index`);

      return {
        // scure keeps txid in natural order; bitcoinjs txInputs.hash uses LE.
        hash: Uint8Array.from(raw.txid).reverse(),
        index: raw.index,
        sequence: raw.sequence ?? 0xffffffff
      };
    });
  }

  setLocktime(locktime: number) {
    if (
      !Number.isSafeInteger(locktime) ||
      locktime < 0 ||
      locktime > 0xffffffff
    )
      throw new Error('Error: locktime must be a uint32');

    const mutableTx = this.#tx as unknown as {
      global?: { fallbackLocktime?: number };
    };
    if (!mutableTx.global || typeof mutableTx.global !== 'object')
      throw new Error(
        'Error: @scure/btc-signer Transaction internals changed; cannot set locktime'
      );
    mutableTx.global.fallbackLocktime = locktime;
  }

  get locktime() {
    return this.#tx.lockTime;
  }

  signInput(index: number, signer: SignerWithPrivateKey) {
    const signed = this.#tx.signIdx(requirePrivateKey(signer), index);
    if (!signed) throw new Error(`Input ${index} was not signed`);
  }

  signAllInputs(signer: SignerWithPrivateKey) {
    const signedInputs = this.#tx.sign(requirePrivateKey(signer));
    if (signedInputs === 0) throw new Error('No inputs were signed');
  }

  signInputHD(index: number, hdSigner: BIP32InterfaceLike) {
    const scureHdSigner = hdSigner;
    const input = this.#tx.getInput(index);
    const tapBip32 = input.tapBip32Derivation;

    if (tapBip32 && tapBip32.length > 0) {
      const fp = uint32FromBytesBE(hdSigner.fingerprint);
      let matchedFingerprint = false;
      let signed = false;
      for (const [, { der }] of tapBip32) {
        if (der.fingerprint !== fp) continue;
        matchedFingerprint = true;
        let derivedNode = scureHdSigner;
        for (const childIndex of der.path)
          derivedNode = derivedNode.derive(childIndex);
        signed =
          this.#tx.signIdx(requirePrivateKey(derivedNode), index) || signed;
      }
      if (!matchedFingerprint)
        throw new Error(
          'No taproot BIP32 derivation matches signer fingerprint'
        );
      if (!signed) throw new Error('No inputs were signed');
    } else {
      const signed = this.#tx.signIdx(toScureHDKey(scureHdSigner), index);
      if (!signed) throw new Error('No inputs were signed');
    }
  }

  signAllInputsHD(hdSigner: BIP32InterfaceLike) {
    let signedInputs = 0;
    for (let i = 0; i < this.#tx.inputsLength; i++) {
      try {
        this.signInputHD(i, hdSigner);
        signedInputs++;
      } catch {
        // Keep parity with bitcoinjs signAllInputs*: skip unsignable inputs.
      }
    }
    if (signedInputs === 0) throw new Error('No inputs were signed');
  }

  finalizeInput(index: number, finalizer?: FinalScriptsFunc) {
    if (finalizer) {
      const rawInput = this.#tx.getInput(index);
      if (!rawInput) throw new Error(`Invalid input index ${index}`);
      const input = scureInputToBitcoinjs(rawInput);
      const witnessUtxo = input.witnessUtxo;
      const redeemScript = input.redeemScript;
      const witnessScript = input.witnessScript;
      const script =
        witnessScript ??
        redeemScript ??
        witnessUtxo?.script ??
        new Uint8Array();
      const result = finalizer(
        index,
        input,
        script,
        !!witnessUtxo,
        !!redeemScript,
        !!witnessScript
      );
      const updateFields: Record<string, unknown> = {};
      if (result.finalScriptSig)
        updateFields['finalScriptSig'] = result.finalScriptSig;
      if (result.finalScriptWitness)
        updateFields['finalScriptWitness'] = RawWitness.decode(
          result.finalScriptWitness
        );
      this.#tx.updateInput(index, updateFields, true);
      return;
    }
    this.#tx.finalizeIdx(index);
  }

  finalizeTaprootInput(
    index: number,
    tapLeafHashToFinalize: Uint8Array | undefined,
    finalizer: () => { finalScriptWitness: Uint8Array }
  ) {
    if (tapLeafHashToFinalize !== undefined)
      throw new Error(
        'Error: scure adapter does not implement tapLeafHashToFinalize in finalizeTaprootInput'
      );
    const result = finalizer();
    this.#tx.updateInput(
      index,
      {
        finalScriptWitness: RawWitness.decode(result.finalScriptWitness)
      },
      true
    );
  }

  validateSignaturesOfInput(
    index: number,
    validator: (
      pubkey: Uint8Array,
      msghash: Uint8Array,
      signature: Uint8Array
    ) => boolean
  ) {
    void validator;
    if (!warnedAboutScureSignatureValidation) {
      console.warn(
        'Warning: @scure/btc-signer adapter does not perform full cryptographic signature validation. Use validate=false to skip validation checks, or use bitcoinjs-lib if full signature validation is required.'
      );
      warnedAboutScureSignatureValidation = true;
    }

    const input = this.#tx.getInput(index);
    if (!input) throw new Error(`Invalid input index ${index}`);
    if (input.tapKeySig) return true;
    if (Array.isArray(input.tapScriptSig) && input.tapScriptSig.length > 0)
      return true;
    return !!(input.partialSig && input.partialSig.length > 0);
  }

  updateInput(index: number, data: PsbtLikeInputUpdate) {
    this.#tx.updateInput(index, toScureInputUpdate(data));
  }

  toBase64() {
    return base64.encode(this.#tx.toPSBT());
  }
}

/** Wrap a raw @scure/btc-signer Transaction into a PsbtLike adapter. */
export function wrapScureTransaction(transaction: btc.Transaction) {
  return new ScurePsbtAdapter(transaction);
}
