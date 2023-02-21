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
  descriptors
}: {
  psbt: Psbt;
  descriptors: DescriptorInterface[];
}) {
  descriptors.forEach((descriptor, inputIndex) =>
    descriptor.finalizePsbtInput({ index: inputIndex, psbt })
  );
}

export { keyExpressionBIP32, keyExpressionLedger } from './keyExpressions';
import * as scriptExpressions from './scriptExpressions';
export { scriptExpressions };

import {
  LedgerState,
  getLedgerMasterFingerPrint,
  getLedgerXpub,
  registerLedgerWallet
} from './ledger';
export const ledger = {
  getLedgerMasterFingerPrint,
  getLedgerXpub,
  registerLedgerWallet
};

export type { LedgerState };
