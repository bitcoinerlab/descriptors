// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * Minimal local subset of the bip174 type surface used by this codebase.
 *
 * This file is intentionally self-contained so the library can stop exposing
 * `bip174` as a dependency.
 */

/** @internal */
export interface KeyValue {
  key: Uint8Array;
  value: Uint8Array;
}

/** @internal */
export interface PartialSig {
  pubkey: Uint8Array;
  signature: Uint8Array;
}

/** @internal */
export interface Bip32Derivation {
  masterFingerprint: Uint8Array;
  pubkey: Uint8Array;
  path: string;
}

/** @internal */
export interface WitnessUtxo {
  script: Uint8Array;
  value: bigint;
}

/** @internal */
export type NonWitnessUtxo = Uint8Array;
/** @internal */
export type SighashType = number;
/** @internal */
export type RedeemScript = Uint8Array;
/** @internal */
export type WitnessScript = Uint8Array;
/** @internal */
export type FinalScriptSig = Uint8Array;
/** @internal */
export type FinalScriptWitness = Uint8Array;
/** @internal */
export type TapKeySig = Uint8Array;
/** @internal */
export type TapInternalKey = Uint8Array;
/** @internal */
export type TapMerkleRoot = Uint8Array;

/** @internal */
export interface TapScriptSig extends PartialSig {
  leafHash: Uint8Array;
}

/** @internal */
export interface TapLeafScript {
  controlBlock: Uint8Array;
  leafVersion: number;
  script: Uint8Array;
}

/** @internal */
export interface TapBip32Derivation extends Bip32Derivation {
  leafHashes: Uint8Array[];
}

/** @internal */
export interface PsbtInputUpdate {
  partialSig?: PartialSig[];
  nonWitnessUtxo?: NonWitnessUtxo;
  witnessUtxo?: WitnessUtxo;
  sighashType?: SighashType;
  redeemScript?: RedeemScript;
  witnessScript?: WitnessScript;
  bip32Derivation?: Bip32Derivation[];
  finalScriptSig?: FinalScriptSig;
  finalScriptWitness?: FinalScriptWitness;
  tapKeySig?: TapKeySig;
  tapScriptSig?: TapScriptSig[];
  tapLeafScript?: TapLeafScript[];
  tapBip32Derivation?: TapBip32Derivation[];
  tapInternalKey?: TapInternalKey;
  tapMerkleRoot?: TapMerkleRoot;
}

/** @internal */
export interface PsbtInput extends PsbtInputUpdate {
  unknownKeyVals?: KeyValue[];
}

/** @internal */
export interface PsbtInputExtended extends PsbtInput {
  [index: string]: unknown;
}

/** @internal */
export function checkForInput(
  inputs: PsbtInput[],
  inputIndex: number
): PsbtInput {
  const input = inputs[inputIndex];
  if (!input) throw new Error(`No input #${inputIndex}`);
  return input;
}
