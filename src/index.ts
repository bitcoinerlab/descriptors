// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { Psbt } from 'bitcoinjs-lib';
import type { DescriptorInterface } from './types';
export {
  DescriptorInterface,
  DescriptorInterfaceConstructor,
  ParseKeyExpression
} from './types';
export { DescriptorsFactory } from './descriptors';
export { DescriptorChecksum as checksum } from './checksum';

import * as signers from './signers';
export { signers };

export function finalizePsbt({
  psbt,
  descriptors,
  validate = true
}: {
  psbt: Psbt;
  descriptors: DescriptorInterface[];
  validate?: boolean | undefined;
}) {
  descriptors.forEach((descriptor, inputIndex) =>
    descriptor.finalizePsbtInput({ index: inputIndex, psbt, validate })
  );
}

export { keyExpressionBIP32, keyExpressionLedger } from './keyExpressions';
import * as scriptExpressions from './scriptExpressions';
export { scriptExpressions };

import { AppClient } from 'ledger';
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
  assertLedgerApp,
  AppClient
};

export type { LedgerState };
