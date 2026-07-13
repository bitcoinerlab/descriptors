/*
 * NOTE: This wrapper is complex for a reason:
 *
 * Extra code exists to preserve 3.x compatibility for:
 * - DescriptorsFactory() / DescriptorsFactory(ecc)
 * - legacy ledgerManager.ecc normalization
 * - deprecated root Ledger helper exports
 * - lazy loading of ./ledger so non-Ledger users do not need
 *   @ledgerhq/ledger-bitcoin installed
 *
 * After removing the 3.x compatibility layer in v4, this file can be exactly
 * this:
 *
 * The optional @ledgerhq/ledger-bitcoin peer remains in 3.x only for these
 * deprecated Ledger shims. The modern /ledger API receives it explicitly in
 * driver.bitcoinApi. Remove the peer together with these shims in v4.
 *
 * ```ts
 * import { createBitcoinjsLib } from '@bitcoinerlab/descriptors-core/bitcoinjs';
 * import * as ecc from '@bitcoinerlab/secp256k1';
 * import { Psbt } from 'bitcoinjs-lib';
 * import { bound } from './backend';
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
 * export const { Output, parseKeyExpression, expand, ECPair, BIP32 } = bound;
 * ```
 */

import * as core from '@bitcoinerlab/descriptors-core';
import { createBitcoinjsLib } from '@bitcoinerlab/descriptors-core/bitcoinjs';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Psbt } from 'bitcoinjs-lib';
import { bound } from './backend';
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
/** @deprecated 3.x root Ledger compatibility only. Remove in v4. */
type LedgerModule = typeof import('./ledger');
/** @deprecated 3.x root Ledger compatibility only. Remove in v4. */
type CompatLedgerParams<Fn> = Fn extends (params: infer Params) => unknown
  ? Omit<Params, 'ledgerManager'> & { ledgerManager: LedgerManager }
  : never;

/**
 * @deprecated Use `Store` from `@bitcoinerlab/descriptors/ledger` for new
 * integrations. Remove this root alias in v4.
 */
export type LedgerState = StrictLedgerState;

/**
 * @deprecated Use `Session` from `@bitcoinerlab/descriptors/ledger`.
 * The root-package type remains only for backwards compatibility with the
 * legacy `ledgerManager.ecc` shortcut. Remove the type in v4.
 */
export type LedgerManager =
  | StrictLedgerManager
  | (Omit<StrictLedgerManager, 'Output'> & {
      /**
       * @deprecated 3.x compatibility only. Remove with `LedgerManager` and
       * `normalizeLedgerPolicyParams(...)` in v4.
       */
      Output?: Bound['Output'];
      /**
       * @deprecated 3.x compatibility only. Remove with the root Ledger
       * helpers and `normalizeLedgerPolicyParams(...)` in v4.
       */
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
 * `DescriptorsFactory` API will be removed in v4.
 */
export function DescriptorsFactory(): Bound;
/**
 * @deprecated Kept only for 3.x backwards compatibility. This root-package
 * `DescriptorsFactory` API will be removed in v4.
 */
export function DescriptorsFactory(ecc: Ecc): Bound;
/**
 * @deprecated Kept only for 3.x backwards compatibility. This root-package
 * `DescriptorsFactory` API will be removed in v4.
 */
export function DescriptorsFactory(bitcoinLib: BitcoinLib): Bound;
export function DescriptorsFactory(eccOrBitcoinLib: Ecc | BitcoinLib = ecc) {
  const bitcoinLib = isBitcoinLib(eccOrBitcoinLib)
    ? eccOrBitcoinLib
    : createBitcoinjsLib(eccOrBitcoinLib || ecc);

  return core.DescriptorsFactory(bitcoinLib);
}

/**
 * @deprecated Lazy loader for 3.x root Ledger exports. Remove with those
 * exports and the optional Ledger peer in v4.
 * @internal
 */
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

/**
 * Casts a released root LedgerManager to the strict compatibility type without
 * activating its backend. Remove this function and all its call sites in v4.
 *
 * @deprecated 3.x root Ledger compatibility only.
 * @internal
 */
function asStrictLedgerParams<Params extends { ledgerManager: LedgerManager }>(
  params: Params
): Omit<Params, 'ledgerManager'> & { ledgerManager: StrictLedgerManager } {
  return params as Omit<Params, 'ledgerManager'> & {
    ledgerManager: StrictLedgerManager;
  };
}

/**
 * Restores the released 3.x `ledgerManager.ecc` shortcut for helpers that parse
 * policies. Remove this function and all its call sites in v4.
 *
 * @deprecated 3.x root Ledger compatibility only.
 * @internal
 */
function normalizeLedgerPolicyParams<
  Params extends { ledgerManager: LedgerManager }
>(
  params: Params
): Omit<Params, 'ledgerManager'> & { ledgerManager: StrictLedgerManager } {
  if (params.ledgerManager.Output || !('ecc' in params.ledgerManager))
    return asStrictLedgerParams(params);

  return {
    ...params,
    ledgerManager: {
      ...params.ledgerManager,
      Output: DescriptorsFactory(params.ledgerManager.ecc).Output
    }
  };
}

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const signInputLedger = (
  params: CompatLedgerParams<LedgerModule['signers']['signInputLedger']>
) =>
  getLedgerModule().signers.signInputLedger(
    normalizeLedgerPolicyParams(params)
  );

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const signLedger = (
  params: CompatLedgerParams<LedgerModule['signers']['signLedger']>
) => getLedgerModule().signers.signLedger(normalizeLedgerPolicyParams(params));

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const deprecatedKeyExpressionLedger = (
  params: CompatLedgerParams<LedgerModule['keyExpressionLedger']>
) => getLedgerModule().keyExpressionLedger(asStrictLedgerParams(params));

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const pkhLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['pkhLedger']>
) =>
  getLedgerModule().scriptExpressions.pkhLedger(asStrictLedgerParams(params));

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const shWpkhLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['shWpkhLedger']>
) =>
  getLedgerModule().scriptExpressions.shWpkhLedger(
    asStrictLedgerParams(params)
  );

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const wpkhLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['wpkhLedger']>
) =>
  getLedgerModule().scriptExpressions.wpkhLedger(asStrictLedgerParams(params));

/** @deprecated 3.x root Ledger delegate. Remove in v4. */
const trLedger = (
  params: CompatLedgerParams<LedgerModule['scriptExpressions']['trLedger']>
) => getLedgerModule().scriptExpressions.trLedger(asStrictLedgerParams(params));

/**
 * Signer helpers.
 *
 * Ledger-related members on this root namespace are deprecated.
 * Use `@bitcoinerlab/descriptors/ledger` instead.
 */
export const signers = {
  ...core.signers,
  /** @deprecated Use `signers.signInput(...)` from the Ledger entrypoint. Remove in v4. */
  signInputLedger,
  /** @deprecated Use `signers.sign(...)` from the Ledger entrypoint. Remove in v4. */
  signLedger
};

/**
 * @deprecated Use `keyExpression(...)` from the Ledger entrypoint. Remove in
 * v4.
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
  /** @deprecated Use `scriptExpressions.pkh(...)` from the Ledger entrypoint. Remove in v4. */
  pkhLedger,
  /** @deprecated Use `scriptExpressions.shWpkh(...)` from the Ledger entrypoint. Remove in v4. */
  shWpkhLedger,
  /** @deprecated Use `scriptExpressions.wpkh(...)` from the Ledger entrypoint. Remove in v4. */
  wpkhLedger,
  /** @deprecated Use `scriptExpressions.tr(...)` from the Ledger entrypoint. Remove in v4. */
  trLedger
};

/**
 * @deprecated Use `@bitcoinerlab/descriptors/ledger`. Remove this root
 * namespace in v4.
 */
export const ledger = {
  assertLedgerApp: (params: Parameters<LedgerModule['assertLedgerApp']>[0]) =>
    getLedgerModule().assertLedgerApp(params),
  getLedgerMasterFingerPrint: (
    params: CompatLedgerParams<LedgerModule['getLedgerMasterFingerPrint']>
  ) =>
    getLedgerModule().getLedgerMasterFingerPrint(asStrictLedgerParams(params)),
  getLedgerXpub: (params: CompatLedgerParams<LedgerModule['getLedgerXpub']>) =>
    getLedgerModule().getLedgerXpub(asStrictLedgerParams(params)),
  registerLedgerWallet: (
    params: CompatLedgerParams<LedgerModule['registerLedgerWallet']>
  ) =>
    getLedgerModule().registerLedgerWallet(normalizeLedgerPolicyParams(params)),
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
