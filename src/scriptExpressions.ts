import { networks, Network } from 'bitcoinjs-lib';
import type { LedgerManager } from './ledger';
import { keyExpressionBIP32, keyExpressionLedger } from './keyExpressions';
import type { BIP32Interface } from 'bip32';

function assertStandardKeyPath(keyPath: string) {
  // Regular expression to match "/change/index" or "/change/*" format
  const regex = /^\/[01]\/(\d+|\*)$/;
  if (!regex.test(keyPath)) {
    throw new Error(
      "Error: Key path must be in the format '/change/index', where change is either 0 or 1 and index is a non-negative integer."
    );
  }
}

function standardExpressionsBIP32Maker(
  purpose: number,
  scriptTemplate: string
) {
  /**
   * Computes the standard descriptor based on given parameters.
   *
   * You can define the output location either by:
   * - Providing the full `keyPath` (e.g., "/0/2").
   * OR
   * - Specifying the `change` and `index` values separately (e.g., `{change:0, index:2}`).
   *
   * For ranged indexing, the `index` can be set as a wildcard '*'. For example:
   * - `keyPath="/0/*"`
   * OR
   * - `{change:0, index:'*'}`.
   */
  function standardScriptExpressionBIP32({
    masterNode,
    network = networks.bitcoin,
    keyPath,
    account,
    change,
    index,
    isPublic = true
  }: {
    masterNode: BIP32Interface;
    /** @default networks.bitcoin */
    network?: Network;
    account: number;
    change?: number | undefined; //0 -> external (receive), 1 -> internal (change)
    index?: number | undefined | '*';
    keyPath?: string;
    /**
     * Compute an xpub or xprv
     * @default true
     */
    isPublic?: boolean;
  }) {
    const originPath = `/${purpose}'/${
      network === networks.bitcoin ? 0 : 1
    }'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const keyExpression = keyExpressionBIP32({
      masterNode,
      originPath,
      keyPath,
      change,
      index,
      isPublic
    });

    return scriptTemplate.replace('KEYEXPRESSION', keyExpression);
  }
  return standardScriptExpressionBIP32;
}
/** @function */
export const pkhBIP32 = standardExpressionsBIP32Maker(44, 'pkh(KEYEXPRESSION)');
/** @function */
export const shWpkhBIP32 = standardExpressionsBIP32Maker(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);
/** @function */
export const wpkhBIP32 = standardExpressionsBIP32Maker(
  84,
  'wpkh(KEYEXPRESSION)'
);
/** @function */
export const trBIP32 = standardExpressionsBIP32Maker(86, 'tr(KEYEXPRESSION)');

function standardExpressionsLedgerMaker(
  purpose: number,
  scriptTemplate: string
) {
  /**
   * Computes the standard descriptor based on given parameters.
   *
   * You can define the output location either by:
   * - Providing the full `keyPath` (e.g., "/0/2").
   * OR
   * - Specifying the `change` and `index` values separately (e.g., `{change:0, index:2}`).
   *
   * For ranged indexing, the `index` can be set as a wildcard '*'. For example:
   * - `keyPath="/0/*"`
   * OR
   * - `{change:0, index:'*'}`.
   */
  async function standardScriptExpressionLedger({
    ledgerManager,
    account,
    keyPath,
    change,
    index
  }: {
    ledgerManager: LedgerManager;
    account: number;
    keyPath?: string;
    change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
    index?: number | undefined | '*';
  }) {
    const { network } = ledgerManager;
    const originPath = `/${purpose}'/${
      network === networks.bitcoin ? 0 : 1
    }'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const keyExpression = await keyExpressionLedger({
      ledgerManager,
      originPath,
      keyPath,
      change,
      index
    });

    return scriptTemplate.replace('KEYEXPRESSION', keyExpression);
  }
  return standardScriptExpressionLedger;
}

/** @function */
export const pkhLedger = standardExpressionsLedgerMaker(
  44,
  'pkh(KEYEXPRESSION)'
);
/** @function */
export const shWpkhLedger = standardExpressionsLedgerMaker(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);
/** @function */
export const wpkhLedger = standardExpressionsLedgerMaker(
  84,
  'wpkh(KEYEXPRESSION)'
);
/** @function */
export const trLedger = standardExpressionsLedgerMaker(86, 'tr(KEYEXPRESSION)');
