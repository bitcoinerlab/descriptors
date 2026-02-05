// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Some dependencies (like hash-base) assume process.version exists.
// In React Native / Hermes, process is defined but version is not.
// Note: we only polyfill if process already exists but is incomplete.
// The user is responsible for providing the process polyfill; this is just
// a small patch for environments (like Hermes) with partial implementations.
//
// More information: https://github.com/browserify/hash-base/issues/21#issuecomment-3476608003
const g: typeof globalThis =
  typeof globalThis !== 'undefined'
    ? globalThis
    : typeof global !== 'undefined'
      ? global
      : ({} as typeof globalThis);
if (
  typeof g.process !== 'undefined' &&
  typeof g.process.version === 'undefined'
) {
  const isDev =
    (g as Record<string, unknown>)['__DEV__'] === true ||
    (g.process as NodeJS.Process)?.env?.['NODE_ENV'] === 'development';

  if (isDev) {
    //only WARN while developing
    console.warn(
      `[bitcoinerlab/descriptors] Polyfilled process.version (missing in this non-Node environment).
Learn more: https://github.com/bitcoinerlab/descriptors/blob/main/src/index.ts#L4`
    );
  }
  // @ts-expect-error Polyfill for environments missing process.version
  global.process.version = '';
}

export type { KeyInfo, Expansion } from './types';
export {
  DescriptorsFactory,
  OutputInstance,
  OutputConstructor
} from './descriptors';
export { DescriptorChecksum as checksum } from './checksum';

import * as signers from './signers';
export { signers };

export { keyExpressionBIP32, keyExpressionLedger } from './keyExpressions';
import * as scriptExpressions from './scriptExpressions';
export { scriptExpressions };

import {
  LedgerState,
  getLedgerMasterFingerPrint,
  getLedgerXpub,
  registerLedgerWallet,
  assertLedgerApp,
  LedgerManager
} from './ledger';

/** @namespace */
export const ledger = {
  /** @function */
  getLedgerMasterFingerPrint,
  /** @function */
  getLedgerXpub,
  /** @function */
  registerLedgerWallet,
  /** @function */
  assertLedgerApp
};

export type { LedgerState, LedgerManager };
