/*
 * NOTE: This wrapper is complex for a reason:
 *
 * There's extra code exists to preserve 3.x compatibility for:
 * - DescriptorsFactory() / DescriptorsFactory(ecc)
 * - legacy ledgerManager.ecc normalization
 * - deprecated root Ledger exports
 * - lazy loading of ./ledger so non-Ledger users do not need
 *   @ledgerhq/ledger-bitcoin installed
 *
 * After next-major version of the lib (allowing breaking changes),
 * this file can be exactly this:
 *
 * ```ts
 * import * as core from '@bitcoinerlab/descriptors-core';
 * import { createBitcoinjsLib } from '@bitcoinerlab/descriptors-core/bitcoinjs';
 * import * as ecc from '@bitcoinerlab/secp256k1';
 * import { Psbt } from 'bitcoinjs-lib';
 *
 * export type {
 *   Expansion,
 *   ExpansionMap,
 *   KeyExpressionParser,
 *   KeyInfo,
 *   Preimage,
 *   TimeConstraints,
 *   TreeNode,
 *   TapTreeNode,
 *   TapTreeInfoNode,
 *   TapLeaf,
 *   TapLeafInfo,
 *   OutputInstance,
 *   OutputConstructor,
 *   Network
 * } from '@bitcoinerlab/descriptors-core';
 *
 * export {
 *   networks,
 *   checksum,
 *   signers,
 *   keyExpressionBIP32,
 *   scriptExpressions
 * } from '@bitcoinerlab/descriptors-core';
 *
 * export { ecc, Psbt };
 *
 * const bound = core.DescriptorsFactory(createBitcoinjsLib(ecc));
 * export const { Output, parseKeyExpression, expand, ECPair, BIP32 } = bound;
 * ```
 */

import * as core from '@bitcoinerlab/descriptors-core';
import { createBitcoinjsLib } from '@bitcoinerlab/descriptors-core/bitcoinjs';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Psbt } from 'bitcoinjs-lib';
import type {
  LedgerManager as StrictLedgerManager,
  LedgerState as StrictLedgerState
} from './ledger';

export type {
  Expansion,
  ExpansionMap,
  KeyExpressionParser,
  KeyInfo,
  Preimage,
  TimeConstraints,
  TreeNode,
  TapTreeNode,
  TapTreeInfoNode,
  TapLeaf,
  TapLeafInfo,
  OutputInstance,
  OutputConstructor,
  Network
} from '@bitcoinerlab/descriptors-core';
export {
  networks,
  checksum,
  keyExpressionBIP32
} from '@bitcoinerlab/descriptors-core';
export { createBitcoinjsLib, ecc, Psbt };

type BitcoinLib = Parameters<typeof core.DescriptorsFactory>[0];
type Ecc = Parameters<typeof createBitcoinjsLib>[0];
type Bound = ReturnType<typeof core.DescriptorsFactory>;
type LedgerModule = typeof import('./ledger');
type CompatLedgerParams<Fn> = Fn extends (params: infer Params) => unknown
  ? Omit<Params, 'ledgerManager'> & { ledgerManager: LedgerManager }
  : never;

/** @deprecated Use `LedgerState` from `@bitcoinerlab/descriptors/ledger`. */
export type LedgerState = StrictLedgerState;

/**
 * @deprecated Use `LedgerManager` from `@bitcoinerlab/descriptors/ledger`.
 * The root-package type remains only for backwards compatibility with the
 * legacy `ledgerManager.ecc` shortcut.
 */
export type LedgerManager =
  | StrictLedgerManager
  | (Omit<StrictLedgerManager, 'Output'> & {
      Output?: Bound['Output'];
      ecc: Ecc;
    });

function isBitcoinLib(
  maybeBitcoinLib: BitcoinLib | Ecc | undefined
): maybeBitcoinLib is BitcoinLib {
  return (
    !!maybeBitcoinLib &&
    typeof maybeBitcoinLib === 'object' &&
    'payments' in maybeBitcoinLib &&
    'script' in maybeBitcoinLib
  );
}

/**
 * @deprecated Kept only for 3.x backwards compatibility. This root-package
 * `DescriptorsFactory` API is planned to disappear in the next major release.
 */
export function DescriptorsFactory(): Bound;
/**
 * @deprecated Kept only for 3.x backwards compatibility. This root-package
 * `DescriptorsFactory` API is planned to disappear in the next major release.
 */
export function DescriptorsFactory(ecc: Ecc): Bound;
/**
 * @deprecated Kept only for 3.x backwards compatibility. This root-package
 * `DescriptorsFactory` API is planned to disappear in the next major release.
 */
export function DescriptorsFactory(bitcoinLib: BitcoinLib): Bound;
export function DescriptorsFactory(eccOrBitcoinLib: Ecc | BitcoinLib = ecc) {
  const bitcoinLib = isBitcoinLib(eccOrBitcoinLib)
    ? eccOrBitcoinLib
    : createBitcoinjsLib(eccOrBitcoinLib || ecc);

  return core.DescriptorsFactory(bitcoinLib);
}

function getLedgerModule() {
  try {
    // This deprecated root package still exposes Ledger helpers for backwards
    // compatibility, but we do not want a static top-level import here.
    //
    // If we imported `./ledger` normally, every consumer of
    // `@bitcoinerlab/descriptors` would pull the Ledger entrypoint into the
    // module graph, which would in turn require the optional
    // `@ledgerhq/ledger-bitcoin` peer even when Ledger is never used.
    //
    // We also avoid switching this to `await import('./ledger')` inside the
    // `try/catch`: in React Native / Metro, conditional dynamic imports inside
    // `try/catch` have historically been analyzed too eagerly once transpiled.
    // See:
    // https://github.com/react-native-community/discussions-and-proposals/issues/120
    //
    // So the compat root uses a local `require()` here, while the modern
    // `@bitcoinerlab/descriptors/ledger` entrypoint uses normal static imports.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require('./ledger') as LedgerModule;
  } catch (error) {
    const errorCode =
      error instanceof Error && 'code' in error
        ? (error as Error & { code?: string }).code
        : undefined;
    if (
      error instanceof Error &&
      (errorCode === 'MODULE_NOT_FOUND' ||
        error.message.includes('@ledgerhq/ledger-bitcoin'))
    ) {
      throw new Error(
        'Could not import "@ledgerhq/ledger-bitcoin". This peer dependency is required when using Ledger helpers from @bitcoinerlab/descriptors. Please run "npm install @ledgerhq/ledger-bitcoin" or import only non-Ledger APIs.'
      );
    }
    throw error;
  }
}

function normalizeLedgerParams<Params extends { ledgerManager: LedgerManager }>(
  params: Params
): Omit<Params, 'ledgerManager'> & { ledgerManager: StrictLedgerManager } {
  if (params.ledgerManager.Output || !('ecc' in params.ledgerManager)) {
    return params as Omit<Params, 'ledgerManager'> & {
      ledgerManager: StrictLedgerManager;
    };
  }

  return {
    ...params,
    ledgerManager: {
      ...params.ledgerManager,
      Output: DescriptorsFactory(params.ledgerManager.ecc).Output
    }
  };
}

const bound: Bound = DescriptorsFactory(ecc);

const signInputLedger = (
  params: CompatLedgerParams<LedgerModule['signers']['signInputLedger']>
) => getLedgerModule().signers.signInputLedger(normalizeLedgerParams(params));

const signLedger = (
  params: CompatLedgerParams<LedgerModule['signers']['signLedger']>
) => getLedgerModule().signers.signLedger(normalizeLedgerParams(params));

const deprecatedKeyExpressionLedger = (
  params: CompatLedgerParams<LedgerModule['keyExpressionLedger']>
) => getLedgerModule().keyExpressionLedger(normalizeLedgerParams(params));

const pkhLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['pkhLedger']>
) =>
  getLedgerModule().scriptExpressions.pkhLedger(normalizeLedgerParams(params));

const shWpkhLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['shWpkhLedger']>
) =>
  getLedgerModule().scriptExpressions.shWpkhLedger(
    normalizeLedgerParams(params)
  );

const wpkhLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['wpkhLedger']>
) =>
  getLedgerModule().scriptExpressions.wpkhLedger(normalizeLedgerParams(params));

const trLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['trLedger']>
) =>
  getLedgerModule().scriptExpressions.trLedger(normalizeLedgerParams(params));

/**
 * Signer helpers.
 *
 * Ledger-related members on this root namespace are deprecated.
 * Use `@bitcoinerlab/descriptors/ledger` instead.
 */
export const signers = {
  ...core.signers,
  signInputLedger,
  signLedger
};

/**
 * @deprecated Use `keyExpressionLedger` from `@bitcoinerlab/descriptors/ledger`.
 */
export const keyExpressionLedger = deprecatedKeyExpressionLedger;

/**
 * Script-expression helpers.
 *
 * Ledger-related members on this root namespace are deprecated.
 * Use `@bitcoinerlab/descriptors/ledger` instead.
 */
export const scriptExpressions = {
  ...core.scriptExpressions,
  pkhLedger,
  shWpkhLedger,
  wpkhLedger,
  trLedger
};

/**
 * @deprecated Use `@bitcoinerlab/descriptors/ledger`.
 */
export const ledger: LedgerModule = {
  assertLedgerApp: params => getLedgerModule().assertLedgerApp(params),
  getLedgerMasterFingerPrint: params =>
    getLedgerModule().getLedgerMasterFingerPrint(normalizeLedgerParams(params)),
  getLedgerXpub: params =>
    getLedgerModule().getLedgerXpub(normalizeLedgerParams(params)),
  registerLedgerWallet: params =>
    getLedgerModule().registerLedgerWallet(normalizeLedgerParams(params)),
  signers: {
    signInputLedger,
    signLedger
  },
  keyExpressionLedger: deprecatedKeyExpressionLedger,
  scriptExpressions: {
    pkhLedger,
    shWpkhLedger,
    wpkhLedger,
    trLedger
  }
};

export const { Output, parseKeyExpression, expand, ECPair, BIP32 } = bound;
