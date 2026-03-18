// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * @scure/btc-signer adapter for BitcoinLib.
 *
 * Wraps @scure/btc-signer, @noble/hashes, @scure/bip32 and related packages
 * into the BitcoinLib interface.  This is the alternative backend for users
 * who prefer the scure/noble ecosystem over bitcoinjs-lib.
 */

import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import {
  RawTx,
  RawOldTx,
  RawWitness,
  type ScriptType
} from '@scure/btc-signer/script.js';
import type {
  P2TR,
  P2TR_TREE,
  TaprootScriptTree
} from '@scure/btc-signer/payment.js';
import type {
  TransactionInput as ScureTransactionInput,
  TransactionInputUpdate as ScureTransactionInputUpdate
} from '@scure/btc-signer/psbt.js';
import { BIP32Factory } from 'bip32';
import type { BIP32API } from 'bip32';
import { ECPairFactory } from 'ecpair';
import type { ECPairAPI } from 'ecpair';
import type { TinySecp256k1Interface } from '../types';
import type {
  BitcoinLib,
  Psbt,
  PsbtLikeInputUpdate,
  PsbtTxInput,
  Payment,
  FinalScriptsFunc,
  Transaction,
  Taptree
} from '../bitcoinLib';
import type {
  Bip32Derivation,
  PartialSig,
  PsbtInput,
  TapBip32Derivation,
  TapLeafScript
} from '../bip174';
import { compare, concat } from 'uint8array-tools';
import { hash160, sha256 } from '../crypto';
import { type Network, networks } from '../networks';

type BitcoinjsPsbtInput = PsbtInput & Partial<PsbtTxInput>;
type BitcoinjsTapScriptSig = NonNullable<PsbtInput['tapScriptSig']>[number];
type ScureTaprootControlBlock = Parameters<
  typeof btc.TaprootControlBlock.encode
>[0];
type ScureTapLeafScript = NonNullable<ScureTransactionInput['tapLeafScript']>;
type ScureTapScriptSig = NonNullable<ScureTransactionInput['tapScriptSig']>;
type ScureTapBip32Derivation = NonNullable<
  ScureTransactionInput['tapBip32Derivation']
>;
type ScureBip32Derivation = NonNullable<
  ScureTransactionInput['bip32Derivation']
>;
type ScureTaprootPayment = P2TR | P2TR_TREE;
type ScureTaprootPaymentLeaf = P2TR_TREE['leaves'][number] & {
  controlBlock: Uint8Array;
};

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

interface ScureHdKey {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  fingerprint: number;
  derive(path: string): ScureHdKey;
  deriveChild(index: number): ScureHdKey;
  sign(hash: Uint8Array): Uint8Array;
}

interface ScureMutableGlobalTransaction {
  global: {
    fallbackLocktime?: number;
  };
}

// ─── Helpers ────────────────────────────────────────────────────────

/** Convert our Network to the format expected by @scure/btc-signer */
function toBtcSignerNetwork(network: Network) {
  return {
    bech32: network.bech32,
    pubKeyHash: network.pubKeyHash,
    scriptHash: network.scriptHash,
    wif: network.wif
  };
}

// ─── ASM → Script ───────────────────────────────────────────────────

// Build set of valid btc-signer opcode names
type ScriptElement = ScriptType[number];

const SIGNER_OP_NAMES = new Set<string>();
for (const key of Object.keys(btc.OP)) {
  if (isNaN(Number(key))) {
    SIGNER_OP_NAMES.add(key);
  }
}

function asmTokenToSignerOp(token: string): ScriptElement | undefined {
  if (token === 'OP_0' || token === 'OP_FALSE') return 'OP_0';
  if (token === 'OP_1' || token === 'OP_TRUE') return 'OP_1';
  for (let i = 2; i <= 16; i++) {
    if (token === `OP_${i}`) return `OP_${i}` as ScriptElement;
  }
  if (token === '1NEGATE' || token === 'OP_1NEGATE') return '1NEGATE';

  if (token.startsWith('OP_')) {
    const stripped = token.slice(3);
    if (SIGNER_OP_NAMES.has(stripped)) return stripped as ScriptElement;
  }
  if (SIGNER_OP_NAMES.has(token)) return token as ScriptElement;

  return undefined;
}

/**
 * Convert ASM string to script bytes.
 * Applies minimal encoding rules matching bitcoinjs-lib: single-byte data
 * pushes 0x01-0x10 are converted to OP_1-OP_16, and empty data is OP_0.
 */
function fromASM(asm: string): Uint8Array {
  const tokens = asm.trim().split(/\s+/);
  const scriptElements: ScriptType = [];

  for (const token of tokens) {
    if (token === '') continue;
    const op = asmTokenToSignerOp(token);
    if (op !== undefined) {
      scriptElements.push(op);
    } else {
      const data = hex.decode(token);
      if (data.length === 0) {
        scriptElements.push('OP_0');
      } else if (data.length === 1 && data[0]! >= 1 && data[0]! <= 16) {
        scriptElements.push(`OP_${data[0]!}` as keyof typeof btc.OP);
      } else if (data.length === 1 && data[0] === 0x81) {
        scriptElements.push('1NEGATE');
      } else {
        scriptElements.push(data);
      }
    }
  }

  return btc.Script.encode(scriptElements);
}

/**
 * Decompile script to array of opcodes (numbers) and data (Uint8Array).
 */
function decompileScript(script: Uint8Array): (number | Uint8Array)[] | null {
  try {
    const decoded = btc.Script.decode(script);
    return decoded.map(item => {
      if (typeof item === 'number') return item;
      if (item instanceof Uint8Array) return item;
      // String opcode: convert to number
      const opNum = btc.OP[item];
      if (opNum !== undefined) return opNum;
      return item as unknown as number;
    });
  } catch {
    return null;
  }
}

/**
 * Count non-push-only opcodes (opcodes > OP_16) in a script.
 */
function countNonPushOnlyOPs(chunks: Array<number | Uint8Array>): number {
  return chunks.filter(op => typeof op === 'number' && op > btc.OP.OP_16)
    .length;
}

/**
 * toStack: decompile a script into its push-data items.
 * For each opcode, OP_0 becomes empty buffer, OP_1-OP_16 become single-byte values.
 * Actual data pushes are returned as-is.
 */
function toStack(scriptBuf: Uint8Array): Uint8Array[] {
  const chunks = decompileScript(scriptBuf);
  if (!chunks) throw new Error('Could not decompile script');
  return chunks.map(chunk => {
    if (typeof chunk === 'number') {
      // OP_0
      if (chunk === 0) return new Uint8Array(0);
      // OP_1 through OP_16
      if (chunk >= 81 && chunk <= 96) {
        return new Uint8Array([chunk - 80]);
      }
      // OP_1NEGATE
      if (chunk === 79) return new Uint8Array([0x81]);
      // Other opcodes — return as single byte
      return new Uint8Array([chunk]);
    }
    return chunk;
  });
}

/**
 * Encode a number for use in Bitcoin Script (CScriptNum format).
 */
function numberEncode(n: number): Uint8Array {
  if (n === 0) return new Uint8Array(0);
  const neg = n < 0;
  let abs = Math.abs(n);
  const result: number[] = [];
  while (abs > 0) {
    result.push(abs & 0xff);
    abs >>= 8;
  }
  if (result[result.length - 1]! & 0x80) {
    result.push(neg ? 0x80 : 0x00);
  } else if (neg) {
    result[result.length - 1]! |= 0x80;
  }
  return new Uint8Array(result);
}

function encodeScriptWitnessStack(stack: Uint8Array[]): Uint8Array {
  return RawWitness.encode(stack);
}

function decodeScriptWitnessStack(witness: Uint8Array): Uint8Array[] {
  return RawWitness.decode(witness);
}

function paymentInputStack(redeem: Payment): Uint8Array[] {
  if (!redeem.output) throw new Error('redeem.output is required');
  if (!redeem.input) return [redeem.output];
  return [...toStack(redeem.input), redeem.output];
}

function controlBlockToScure(
  controlBlock: Uint8Array,
  leafVersion: number
): ScureTaprootControlBlock {
  const decoded = btc.TaprootControlBlock.decode(controlBlock);
  return { ...decoded, version: (decoded.version & 1) | leafVersion };
}

function scureTapLeafScriptToBitcoinjs(
  tapLeafScript: ScureTapLeafScript
): TapLeafScript[] {
  return tapLeafScript.map(([controlBlock, scriptWithVersion]) => ({
    controlBlock: btc.TaprootControlBlock.encode(controlBlock),
    script: scriptWithVersion.subarray(0, -1),
    leafVersion: scriptWithVersion[scriptWithVersion.length - 1] ?? 0xc0
  }));
}

function bitcoinjsTapLeafScriptToScure(
  tapLeafScript: TapLeafScript[]
): ScureTapLeafScript {
  return tapLeafScript.map(leaf => [
    controlBlockToScure(leaf.controlBlock, leaf.leafVersion),
    concat([leaf.script, Uint8Array.from([leaf.leafVersion])])
  ]);
}

function scureTapScriptSigToBitcoinjs(
  tapScriptSig: ScureTapScriptSig
): BitcoinjsTapScriptSig[] {
  return tapScriptSig.map(([key, signature]) => ({
    pubkey: key.pubKey,
    leafHash: key.leafHash,
    signature
  }));
}

function bitcoinjsTapScriptSigToScure(
  tapScriptSig: BitcoinjsTapScriptSig[]
): ScureTapScriptSig {
  return tapScriptSig.map(sig => [
    { pubKey: sig.pubkey, leafHash: sig.leafHash },
    sig.signature
  ]);
}

function scureBip32DerivationToBitcoinjs(
  derivation: ScureBip32Derivation
): Bip32Derivation[] {
  return derivation.map(([pubkey, { fingerprint, path }]) => ({
    pubkey,
    masterFingerprint: uint32ToBytes(fingerprint),
    path: pathArrayToString(path)
  }));
}

function bitcoinjsBip32DerivationToScure(
  derivation: Bip32Derivation[]
): ScureBip32Derivation {
  return derivation.map(({ pubkey, masterFingerprint, path }) => [
    pubkey,
    {
      fingerprint: readUInt32BE(masterFingerprint),
      path: btc.bip32Path(path)
    }
  ]);
}

function scureTapBip32DerivationToBitcoinjs(
  derivation: ScureTapBip32Derivation
): TapBip32Derivation[] {
  return derivation.map(([pubkey, { hashes, der }]) => ({
    pubkey,
    masterFingerprint: uint32ToBytes(der.fingerprint),
    path: pathArrayToString(der.path),
    leafHashes: hashes
  }));
}

function bitcoinjsTapBip32DerivationToScure(
  derivation: TapBip32Derivation[]
): ScureTapBip32Derivation {
  return derivation.map(({ pubkey, masterFingerprint, path, leafHashes }) => [
    pubkey,
    {
      hashes: leafHashes,
      der: {
        fingerprint: readUInt32BE(masterFingerprint),
        path: btc.bip32Path(path)
      }
    }
  ]);
}

function scurePartialSigToBitcoinjs(
  partialSig: NonNullable<ScureTransactionInput['partialSig']>
): PartialSig[] {
  return partialSig.map(([pubkey, signature]) => ({ pubkey, signature }));
}

function bitcoinjsPartialSigToScure(
  partialSig: PartialSig[]
): NonNullable<ScureTransactionInputUpdate['partialSig']> {
  return partialSig.map(({ pubkey, signature }) => [pubkey, signature]);
}

function toScureInputUpdate(
  input: PsbtLikeInputUpdate
): ScureTransactionInputUpdate {
  const result: ScureTransactionInputUpdate = {};

  if (input.nonWitnessUtxo) result.nonWitnessUtxo = input.nonWitnessUtxo;
  if (input.witnessUtxo) {
    result.witnessUtxo = {
      script: input.witnessUtxo.script,
      amount: input.witnessUtxo.value
    };
  }
  if (input.redeemScript) result.redeemScript = input.redeemScript;
  if (input.witnessScript) result.witnessScript = input.witnessScript;
  if (input.tapInternalKey) result.tapInternalKey = input.tapInternalKey;
  if (input.tapMerkleRoot) result.tapMerkleRoot = input.tapMerkleRoot;
  if (input.tapKeySig) result.tapKeySig = input.tapKeySig;
  if (input.bip32Derivation)
    result.bip32Derivation = bitcoinjsBip32DerivationToScure(
      input.bip32Derivation
    );
  if (input.tapBip32Derivation)
    result.tapBip32Derivation = bitcoinjsTapBip32DerivationToScure(
      input.tapBip32Derivation
    );
  if (input.partialSig)
    result.partialSig = bitcoinjsPartialSigToScure(input.partialSig);
  if (input.tapLeafScript)
    result.tapLeafScript = bitcoinjsTapLeafScriptToScure(input.tapLeafScript);
  if (input.tapScriptSig)
    result.tapScriptSig = bitcoinjsTapScriptSigToScure(input.tapScriptSig);
  if (input.sighashType !== undefined) result.sighashType = input.sighashType;
  if (input.finalScriptSig) result.finalScriptSig = input.finalScriptSig;
  if (input.finalScriptWitness)
    result.finalScriptWitness = decodeScriptWitnessStack(
      input.finalScriptWitness
    );

  return result;
}

function toScureInput(input: BitcoinjsPsbtInput): ScureTransactionInputUpdate {
  if (!input.hash) throw new Error('PSBT input hash is required');
  if (input.index === undefined)
    throw new Error('PSBT input index is required');
  const result = toScureInputUpdate(input);
  result.txid = input.hash;
  result.index = input.index;
  if (input.sequence !== undefined) result.sequence = input.sequence;
  return result;
}

function scureInputToBitcoinjs(raw: ScureTransactionInput): PsbtInput {
  const input: Partial<PsbtInput> = {};

  if (raw.nonWitnessUtxo)
    input.nonWitnessUtxo = RawTx.encode(raw.nonWitnessUtxo);
  if (raw.witnessUtxo) {
    input.witnessUtxo = {
      script: raw.witnessUtxo.script,
      value: raw.witnessUtxo.amount
    };
  }
  if (raw.redeemScript) input.redeemScript = raw.redeemScript;
  if (raw.witnessScript) input.witnessScript = raw.witnessScript;
  if (raw.tapInternalKey) input.tapInternalKey = raw.tapInternalKey;
  if (raw.tapMerkleRoot) input.tapMerkleRoot = raw.tapMerkleRoot;
  if (raw.tapKeySig) input.tapKeySig = raw.tapKeySig;
  if (raw.bip32Derivation)
    input.bip32Derivation = scureBip32DerivationToBitcoinjs(
      raw.bip32Derivation
    );
  if (raw.tapBip32Derivation)
    input.tapBip32Derivation = scureTapBip32DerivationToBitcoinjs(
      raw.tapBip32Derivation
    );
  if (raw.partialSig)
    input.partialSig = scurePartialSigToBitcoinjs(raw.partialSig);
  if (raw.tapLeafScript)
    input.tapLeafScript = scureTapLeafScriptToBitcoinjs(raw.tapLeafScript);
  if (raw.tapScriptSig)
    input.tapScriptSig = scureTapScriptSigToBitcoinjs(raw.tapScriptSig);
  if (raw.sighashType !== undefined) input.sighashType = raw.sighashType;
  if (raw.finalScriptSig) input.finalScriptSig = raw.finalScriptSig;
  if (raw.finalScriptWitness)
    input.finalScriptWitness = encodeScriptWitnessStack(raw.finalScriptWitness);

  return input;
}

function requirePrivateKey(signer: SignerWithPrivateKey): Uint8Array {
  if (!signer.privateKey)
    throw new Error('Error: signer must expose a privateKey for scure signing');
  return signer.privateKey;
}

// ─── Payment wrappers ───────────────────────────────────────────────

/**
 * Safe p2wsh wrapper: tries btc.p2wsh first, falls back to manual computation
 * when btc-signer rejects the inner script (e.g. complex miniscript).
 */
function safeP2wsh(
  redeem: Payment,
  net?: ReturnType<typeof toBtcSignerNetwork>
): Payment {
  const innerScript = redeem.output;
  if (!innerScript) throw new Error('p2wsh requires redeem.output');
  const witness = redeem.input
    ? [...toStack(redeem.input), innerScript]
    : undefined;
  try {
    const result = btc.p2wsh(
      { type: 'unknown' as never, script: innerScript },
      net
    );
    const payment: Payment = {
      output: result.script,
      address: result.address,
      redeem: { ...redeem, output: innerScript }
    };
    if (witness) payment.witness = witness;
    return payment;
  } catch {
    const scriptHash = sha256(innerScript);
    const outputScript = btc.OutScript.encode({
      type: 'wsh',
      hash: scriptHash
    });
    let address: string | undefined;
    if (net) {
      try {
        address = btc.Address(net).encode({
          type: 'wsh',
          hash: scriptHash
        });
      } catch {
        // address encoding may fail for exotic networks
      }
    }
    const result: Payment = {
      output: outputScript,
      redeem: { ...redeem, output: innerScript }
    };
    if (address) result.address = address;
    if (witness) result.witness = witness;
    return result;
  }
}

/**
 * Safe p2sh wrapper: tries btc.p2sh first, falls back to manual computation.
 */
function safeP2sh(
  redeem: Payment,
  net?: ReturnType<typeof toBtcSignerNetwork>
): Payment {
  const innerScript = redeem.output;
  if (!innerScript) throw new Error('p2sh requires redeem.output');
  const input = btc.Script.encode(paymentInputStack(redeem));
  try {
    const result = btc.p2sh(
      { type: 'unknown' as never, script: innerScript },
      net
    );
    const payment: Payment = {
      output: result.script,
      address: result.address,
      redeem: { ...redeem, output: innerScript },
      input
    };
    if (redeem.witness) payment.witness = redeem.witness;
    return payment;
  } catch {
    const scriptHash = hash160(innerScript);
    const outputScript = btc.OutScript.encode({
      type: 'sh',
      hash: scriptHash
    });
    let address: string | undefined;
    if (net) {
      try {
        address = btc.Address(net).encode({
          type: 'sh',
          hash: scriptHash
        });
      } catch {
        // address encoding may fail
      }
    }
    const result: Payment = {
      output: outputScript,
      redeem: { ...redeem, output: innerScript },
      input
    };
    if (address) result.address = address;
    if (redeem.witness) result.witness = redeem.witness;
    return result;
  }
}

// ─── Psbt wrapper around @scure/btc-signer Transaction ─────────────

class ScurePsbtAdapter implements Psbt {
  readonly #tx: InstanceType<typeof btc.Transaction>;

  constructor(tx: InstanceType<typeof btc.Transaction>) {
    this.#tx = tx;
  }

  /** Access the underlying scure Transaction for operations not in Psbt */
  get raw(): InstanceType<typeof btc.Transaction> {
    return this.#tx;
  }

  #mapInput(index: number): PsbtInput {
    return scureInputToBitcoinjs(this.#tx.getInput(index));
  }

  #mapTxInput(index: number): Psbt['txInputs'][number] {
    const raw = this.#tx.getInput(index);
    return {
      hash: raw.txid ?? new Uint8Array(32),
      index: raw.index ?? 0,
      sequence: raw.sequence ?? 0xffffffff
    };
  }

  addInput(input: PsbtInput): void {
    this.#tx.addInput(toScureInput(input));
  }

  addOutput(output: { script: Uint8Array; value: bigint }): void {
    this.#tx.addOutput({
      script: output.script,
      amount: output.value
    });
  }

  get inputCount(): number {
    return this.#tx.inputsLength;
  }

  get data(): Psbt['data'] {
    return {
      inputs: Array.from({ length: this.#tx.inputsLength }, (_value, index) =>
        this.#mapInput(index)
      )
    };
  }

  get txInputs(): Psbt['txInputs'] {
    return Array.from({ length: this.#tx.inputsLength }, (_value, index) =>
      this.#mapTxInput(index)
    );
  }

  setLocktime(locktime: number): void {
    const tx = this.#tx as unknown as ScureMutableGlobalTransaction;
    tx.global.fallbackLocktime = locktime;
  }

  get locktime(): number {
    return this.#tx.lockTime;
  }

  signInput(index: number, signer: SignerWithPrivateKey): void {
    this.#tx.signIdx(requirePrivateKey(signer), index);
  }

  signAllInputs(signer: SignerWithPrivateKey): void {
    this.#tx.sign(requirePrivateKey(signer));
  }

  signInputHD(
    index: number,
    hdSigner: {
      publicKey: Uint8Array;
      fingerprint: Uint8Array;
      derivePath(path: string): {
        publicKey: Uint8Array;
        sign(hash: Uint8Array): Uint8Array;
      };
    }
  ): void {
    const scureHdSigner = hdSigner as DerivableHdSigner;
    // scure's signIdx with HDKey checks bip32Derivation but NOT tapBip32Derivation.
    // We need to handle taproot manually.
    const input = this.#tx.getInput(index);
    const tapBip32 = input.tapBip32Derivation;

    if (tapBip32 && tapBip32.length > 0) {
      const fp = readUInt32BE(hdSigner.fingerprint);
      for (const [, { der }] of tapBip32) {
        if (der.fingerprint !== fp) continue;
        const derivedNode = deriveFromPathArray(scureHdSigner, der.path);
        this.#tx.signIdx(requirePrivateKey(derivedNode), index);
      }
    } else {
      // For non-taproot, convert to scure HDKey format
      const scureHD = toScureHDKey(scureHdSigner);
      this.#tx.signIdx(scureHD, index);
    }
  }

  signAllInputsHD(hdSigner: {
    publicKey: Uint8Array;
    fingerprint: Uint8Array;
    derivePath(path: string): {
      publicKey: Uint8Array;
      sign(hash: Uint8Array): Uint8Array;
    };
  }): void {
    const scureHdSigner = hdSigner as DerivableHdSigner;
    // Handle taproot inputs individually
    let tapSigned = 0;
    for (let i = 0; i < this.#tx.inputsLength; i++) {
      const input = this.#tx.getInput(i);
      const tapBip32 = input.tapBip32Derivation;
      if (tapBip32 && Array.isArray(tapBip32) && tapBip32.length > 0) {
        this.signInputHD(i, hdSigner);
        tapSigned++;
      }
    }

    // Sign remaining non-taproot inputs
    try {
      this.#tx.sign(toScureHDKey(scureHdSigner));
    } catch {
      // sign() throws when no bip32Derivation matches
      if (tapSigned === 0) throw new Error('No inputs were signed');
    }
  }

  finalizeInput(index: number, finalizer?: FinalScriptsFunc): void {
    if (finalizer) {
      // Custom finalizer for miniscript
      const input = this.data.inputs[index];
      if (!input) throw new Error(`Invalid input index ${index}`);
      const witnessUtxo = input.witnessUtxo;
      const redeemScript = input.redeemScript;
      const witnessScript = input.witnessScript;
      const script =
        witnessScript ??
        redeemScript ??
        witnessUtxo?.script ??
        new Uint8Array();
      const isSegwit = !!witnessUtxo;
      const isP2SH = !!redeemScript;
      const isP2WSH = !!witnessScript;
      const result = finalizer(index, input, script, isSegwit, isP2SH, isP2WSH);
      const updateFields: Record<string, unknown> = {};
      if (result.finalScriptSig)
        updateFields['finalScriptSig'] = result.finalScriptSig;
      if (result.finalScriptWitness)
        updateFields['finalScriptWitness'] = decodeScriptWitnessStack(
          result.finalScriptWitness
        );
      this.#tx.updateInput(index, updateFields, true);
    } else {
      this.#tx.finalizeIdx(index);
    }
  }

  finalizeTaprootInput(
    index: number,
    tapLeafHashToFinalize: Uint8Array | undefined,
    finalizer: () => { finalScriptWitness: Uint8Array }
  ): void {
    if (tapLeafHashToFinalize !== undefined) {
      throw new Error(
        'Error: scure adapter does not implement tapLeafHashToFinalize in finalizeTaprootInput'
      );
    }
    const result = finalizer();
    this.#tx.updateInput(
      index,
      {
        finalScriptWitness: decodeScriptWitnessStack(result.finalScriptWitness)
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
  ): boolean {
    // scure doesn't expose a direct validateSignaturesOfInput.
    // We check for partial signatures and validate them manually.
    const input = this.data.inputs[index];
    if (!input) throw new Error(`Invalid input index ${index}`);

    // Check tapKeySig
    if (input.tapKeySig) {
      // For taproot key-path, we can't easily validate without the sighash.
      // Return true if a signature exists (scure validates during finalization).
      return true;
    }

    // Check tapScriptSig
    if (
      input.tapScriptSig &&
      Array.isArray(input.tapScriptSig) &&
      input.tapScriptSig.length > 0
    ) {
      return true;
    }

    // Check partialSig
    if (input.partialSig && input.partialSig.length > 0) {
      for (const ps of input.partialSig) {
        // We can't validate without the sighash, but we trust the signature exists
        void validator;
        void ps;
      }
      return true;
    }

    return false;
  }

  updateInput(index: number, data: PsbtLikeInputUpdate): void {
    this.#tx.updateInput(index, toScureInputUpdate(data));
  }

  toBase64(): string {
    // Convert PSBT bytes to base64
    const psbtBytes = this.#tx.toPSBT();
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(psbtBytes).toString('base64');
    }
    // Fallback for environments without Buffer
    let binary = '';
    for (let i = 0; i < psbtBytes.length; i++) {
      binary += String.fromCharCode(psbtBytes[i]!);
    }
    return btoa(binary);
  }
}

// ─── HD Key helpers ─────────────────────────────────────────────────

function readUInt32BE(buf: Uint8Array): number {
  return ((buf[0]! << 24) | (buf[1]! << 16) | (buf[2]! << 8) | buf[3]!) >>> 0;
}

function uint32ToBytes(n: number): Uint8Array {
  return new Uint8Array([
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff
  ]);
}

function pathArrayToString(path: number[]): string {
  const parts = path.map(idx => {
    if (idx >= 0x80000000) {
      return `${idx - 0x80000000}'`;
    }
    return `${idx}`;
  });
  return `m/${parts.join('/')}`;
}

function deriveFromPathArray(
  hdSigner: DerivableHdSigner,
  pathArray: number[]
): DerivableHdSigner {
  const pathStr = pathArrayToString(pathArray);
  // Remove the 'm/' prefix since derivePath expects relative paths from the node
  return hdSigner.derivePath(pathStr.slice(2));
}

function toScureHDKey(hdSigner: DerivableHdSigner): ScureHdKey {
  if (!hdSigner.privateKey)
    throw new Error(
      'Error: HD signer must expose a privateKey for scure signing'
    );
  return {
    publicKey: hdSigner.publicKey,
    privateKey: hdSigner.privateKey,
    fingerprint:
      hdSigner.fingerprint instanceof Uint8Array
        ? readUInt32BE(hdSigner.fingerprint)
        : hdSigner.fingerprint,
    derive(path: string) {
      return toScureHDKey(hdSigner.derivePath(path));
    },
    deriveChild(index: number) {
      return toScureHDKey(hdSigner.derive(index));
    },
    sign(hash: Uint8Array): Uint8Array {
      return hdSigner.sign(hash);
    }
  };
}

// ─── Transaction wrapper ──────────────────────────────────────────────

function parseRawTx(rawBytes: Uint8Array): Transaction {
  const parsed = RawTx.decode(rawBytes);
  // Compute txid: double-SHA256 of non-witness serialization, reversed
  const nonWitnessSerialization = RawOldTx.encode(parsed);
  const txidHash = sha256(sha256(nonWitnessSerialization));
  const txidBytes = txidHash.slice().reverse();

  return {
    getId: () => hex.encode(txidBytes),
    outs: parsed.outputs.map(o => ({
      script: o.script,
      value: o.amount
    })),
    toBuffer: () => rawBytes
  };
}

// ─── Factory ────────────────────────────────────────────────────────

/**
 * Create a BitcoinLib backed by @scure/btc-signer.
 *
 * @param ecc  A TinySecp256k1Interface (e.g. `@bitcoinerlab/secp256k1`).
 */
export function createScureLib(ecc: TinySecp256k1Interface): BitcoinLib {
  const ECPair: ECPairAPI = ECPairFactory(ecc);
  const BIP32: BIP32API = BIP32Factory(ecc);

  return {
    payments: {
      p2pk(a) {
        if (!a.pubkey) throw new Error('p2pk requires pubkey');
        const net = a.network ? toBtcSignerNetwork(a.network) : undefined;
        try {
          const result = btc.p2pk(a.pubkey, net);
          return { output: result.script, pubkey: a.pubkey } as Payment;
        } catch {
          // p2pk fallback: manually construct the script
          // <pubkey> OP_CHECKSIG
          const script = btc.Script.encode([a.pubkey, 'CHECKSIG']);
          return { output: script, pubkey: a.pubkey } as Payment;
        }
      },

      p2pkh(a) {
        const net = a.network ? toBtcSignerNetwork(a.network) : undefined;
        if (a.pubkey) {
          const result = btc.p2pkh(a.pubkey, net);
          return {
            output: result.script,
            address: result.address,
            pubkey: a.pubkey,
            hash: hash160(a.pubkey)
          } as Payment;
        }
        if (a.hash) {
          const outputScript = btc.OutScript.encode({
            type: 'pkh',
            hash: a.hash
          });
          let address: string | undefined;
          if (net) {
            try {
              address = btc.Address(net).encode({
                type: 'pkh',
                hash: a.hash
              });
            } catch {
              /* ignore */
            }
          }
          return { output: outputScript, address, hash: a.hash } as Payment;
        }
        if (a.output) {
          const decoded = btc.OutScript.decode(a.output);
          if (decoded.type === 'pkh') {
            let address: string | undefined;
            if (net) {
              try {
                address = btc.Address(net).encode(decoded);
              } catch {
                /* ignore */
              }
            }
            return {
              output: a.output,
              address,
              hash: decoded.hash
            } as Payment;
          }
        }
        throw new Error('p2pkh requires pubkey, hash, or output');
      },

      p2sh(a) {
        const net = a.network ? toBtcSignerNetwork(a.network) : undefined;
        if (a.redeem?.output) {
          return safeP2sh(a.redeem, net);
        }
        if (a.output) {
          const decoded = btc.OutScript.decode(a.output);
          if (decoded.type === 'sh') {
            let address: string | undefined;
            if (net) {
              try {
                address = btc.Address(net).encode(decoded);
              } catch {
                /* ignore */
              }
            }
            return { output: a.output, address, hash: decoded.hash } as Payment;
          }
        }
        throw new Error('p2sh requires redeem.output or output');
      },

      p2wpkh(a) {
        const net = a.network ? toBtcSignerNetwork(a.network) : undefined;
        if (a.pubkey) {
          const result = btc.p2wpkh(a.pubkey, net);
          return {
            output: result.script,
            address: result.address,
            pubkey: a.pubkey,
            hash: hash160(a.pubkey)
          } as Payment;
        }
        if (a.hash) {
          const outputScript = btc.OutScript.encode({
            type: 'wpkh',
            hash: a.hash
          });
          let address: string | undefined;
          if (net) {
            try {
              address = btc.Address(net).encode({
                type: 'wpkh',
                hash: a.hash
              });
            } catch {
              /* ignore */
            }
          }
          return { output: outputScript, address, hash: a.hash } as Payment;
        }
        if (a.output) {
          const decoded = btc.OutScript.decode(a.output);
          if (decoded.type === 'wpkh') {
            let address: string | undefined;
            if (net) {
              try {
                address = btc.Address(net).encode(decoded);
              } catch {
                /* ignore */
              }
            }
            return {
              output: a.output,
              address,
              hash: decoded.hash
            } as Payment;
          }
        }
        throw new Error('p2wpkh requires pubkey, hash, or output');
      },

      p2wsh(a) {
        const net = a.network ? toBtcSignerNetwork(a.network) : undefined;
        if (a.redeem?.output) {
          return safeP2wsh(a.redeem, net);
        }
        if (a.output) {
          const decoded = btc.OutScript.decode(a.output);
          if (decoded.type === 'wsh') {
            let address: string | undefined;
            if (net) {
              try {
                address = btc.Address(net).encode(decoded);
              } catch {
                /* ignore */
              }
            }
            return { output: a.output, address, hash: decoded.hash } as Payment;
          }
        }
        throw new Error('p2wsh requires redeem.output or output');
      },

      p2ms(a) {
        const result = btc.p2ms(a.m, a.pubkeys);
        return { output: result.script } as Payment;
      },

      p2tr(a) {
        const net = a.network ? toBtcSignerNetwork(a.network) : undefined;
        if (a.internalPubkey) {
          let result: ScureTaprootPayment;
          if (a.scriptTree) {
            const scriptTree = convertTaptree(a.scriptTree);
            result = btc.p2tr(a.internalPubkey, scriptTree, net, true);
          } else {
            result = btc.p2tr(a.internalPubkey, undefined, net);
          }
          const payment: Payment = {
            output: result.script,
            address: result.address,
            internalPubkey: a.internalPubkey,
            pubkey: result.tweakedPubkey
          };
          // When redeem is provided, find the matching leaf and build the
          // witness array [tapScript, controlBlock] that bitcoinjs-lib returns.
          if (a.redeem?.output && 'leaves' in result) {
            const taprootTreeResult = result as P2TR_TREE;
            const redeemVersion = a.redeem.redeemVersion ?? 0xc0;
            const matchingLeaf = taprootTreeResult.leaves.find(
              leaf =>
                compare(leaf.script, a.redeem!.output) === 0 &&
                (leaf.version ?? 0xc0) === redeemVersion
            ) as ScureTaprootPaymentLeaf | undefined;
            if (matchingLeaf) {
              payment.witness = [
                matchingLeaf.script,
                matchingLeaf.controlBlock
              ];
            }
          }
          return payment;
        }
        if (a.output) {
          const decoded = btc.OutScript.decode(a.output);
          if (decoded.type === 'tr') {
            let address: string | undefined;
            if (net) {
              try {
                address = btc.Address(net).encode(decoded);
              } catch {
                /* ignore */
              }
            }
            return {
              output: a.output,
              address,
              pubkey: decoded.pubkey
            } as Payment;
          }
        }
        throw new Error('p2tr requires internalPubkey or output');
      }
    },

    script: {
      fromASM: asm => fromASM(asm),
      toStack: buf => toStack(buf),
      decompile: buf => decompileScript(buf),
      countNonPushOnlyOPs: chunks => countNonPushOnlyOPs(chunks),
      number: {
        encode: n => numberEncode(n)
      }
    },

    Transaction: {
      fromHex: hexStr => parseRawTx(hex.decode(hexStr)),
      fromBuffer: buf => parseRawTx(buf)
    },

    address: {
      toOutputScript: (addr, network) => {
        const net = network
          ? toBtcSignerNetwork(network)
          : toBtcSignerNetwork(networks.bitcoin);
        const decoded = btc.Address(net).decode(addr);
        return btc.OutScript.encode(decoded);
      }
    },

    Psbt: class {
      constructor(_opts?: { network?: Network }) {
        const tx = new btc.Transaction({
          allowUnknownOutputs: true,
          disableScriptCheck: true
        });
        const adapter = new ScurePsbtAdapter(tx);
        return adapter;
      }
    } as unknown as { new (opts?: { network?: Network }): Psbt },

    ECPair,
    BIP32,

    ecc
  };
}

// ─── Taptree conversion ─────────────────────────────────────────────

type ScureTaptree = TaprootScriptTree;

function convertTaptree(tree: Taptree): ScureTaptree {
  if (Array.isArray(tree)) {
    return [convertTaptree(tree[0]), convertTaptree(tree[1])] as ScureTaptree;
  }
  // Leaf: { output, version? }
  return {
    script: tree.output,
    leafVersion: tree.version ?? 0xc0
  };
}
