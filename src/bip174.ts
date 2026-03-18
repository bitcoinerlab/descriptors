// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * Minimal local subset of the bip174 type surface used by this codebase.
 *
 * This file is intentionally self-contained so the library can stop exposing
 * `bip174` as a dependency.
 */

export interface KeyValue {
  key: Uint8Array;
  value: Uint8Array;
}

export interface PartialSig {
  pubkey: Uint8Array;
  signature: Uint8Array;
}

export interface Bip32Derivation {
  masterFingerprint: Uint8Array;
  pubkey: Uint8Array;
  path: string;
}

export interface WitnessUtxo {
  script: Uint8Array;
  value: bigint;
}

export type NonWitnessUtxo = Uint8Array;
export type SighashType = number;
export type RedeemScript = Uint8Array;
export type WitnessScript = Uint8Array;
export type FinalScriptSig = Uint8Array;
export type FinalScriptWitness = Uint8Array;
export type TapKeySig = Uint8Array;
export type TapInternalKey = Uint8Array;
export type TapMerkleRoot = Uint8Array;

export interface TapScriptSig extends PartialSig {
  leafHash: Uint8Array;
}

export interface TapLeafScript {
  controlBlock: Uint8Array;
  leafVersion: number;
  script: Uint8Array;
}

export interface TapBip32Derivation extends Bip32Derivation {
  leafHashes: Uint8Array[];
}

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

export interface PsbtInput extends PsbtInputUpdate {
  unknownKeyVals?: KeyValue[];
}

export interface PsbtInputExtended extends PsbtInput {
  [index: string]: unknown;
}

export function checkForInput(
  inputs: PsbtInput[],
  inputIndex: number
): PsbtInput {
  const input = inputs[inputIndex];
  if (!input) throw new Error(`No input #${inputIndex}`);
  return input;
}
