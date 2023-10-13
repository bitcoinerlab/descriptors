// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

export type { KeyInfo, Expansion } from './types';
import type { Psbt } from 'bitcoinjs-lib';
import type { DescriptorInstance, OutputInstance } from './descriptors';
export {
  DescriptorsFactory,
  DescriptorInstance,
  DescriptorConstructor,
  OutputInstance,
  OutputConstructor
} from './descriptors';
export { DescriptorChecksum as checksum } from './checksum';

import * as signers from './signers';
export { signers };

/**
 * To finalize the `psbt`, you can either call the method
 * `output.finalizePsbtInput({ index, psbt })` on each descriptor, passing as
 * arguments the `psbt` and its input `index`, or call this helper function:
 * `finalizePsbt({psbt, outputs })`. In the latter case, `outputs` is an
 * array of {@link _Internal_.Output | Output elements} ordered in the array by
 * their respective input index in the `psbt`.
 */
function finalizePsbt(params: {
  psbt: Psbt;
  outputs: OutputInstance[];
  validate?: boolean | undefined;
}): void;

/**
 * @deprecated
 * @hidden
 * To be removed in version 3.0
 */
function finalizePsbt(params: {
  psbt: Psbt;
  descriptors: DescriptorInstance[];
  validate?: boolean | undefined;
}): void;
/**
 * @hidden
 * To be removed in v3.0 and replaced by the version with the signature that
 * does not accept descriptors
 */
function finalizePsbt({
  psbt,
  outputs,
  descriptors,
  validate = true
}: {
  psbt: Psbt;
  outputs?: OutputInstance[];
  descriptors?: DescriptorInstance[];
  validate?: boolean | undefined;
}) {
  if (descriptors && outputs)
    throw new Error(`descriptors param has been deprecated`);
  outputs = descriptors || outputs;
  if (!outputs) throw new Error(`outputs not provided`);
  outputs.forEach((output, inputIndex) =>
    output.finalizePsbtInput({ index: inputIndex, psbt, validate })
  );
}

export { finalizePsbt };

export { keyExpressionBIP32, keyExpressionLedger } from './keyExpressions';
import * as scriptExpressions from './scriptExpressions';
export { scriptExpressions };

import {
  LedgerState,
  getLedgerMasterFingerPrint,
  getLedgerXpub,
  registerLedgerWallet,
  assertLedgerApp
} from './ledger';
export const ledger = {
  getLedgerMasterFingerPrint,
  getLedgerXpub,
  registerLedgerWallet,
  assertLedgerApp
};

export type { LedgerState };
