import type { BIP32InterfaceLike, ScureHDKeyLike } from './bitcoinLib';
import { keyExpressionBIP32 } from './keyExpressions';
import { coinTypeFromNetwork } from './networkUtils';
import { type Network, networks } from './networks';

export function assertStandardKeyPath(keyPath: string) {
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
   *
   * @param {Object} params - The parameters object.
   * @param {BIP32InterfaceLike | ScureHDKeyLike} params.masterNode - Root HD node.
   * Pass a bitcoinjs {@link https://github.com/bitcoinjs/bip32 | `BIP32`} node
   * or a scure {@link https://github.com/paulmillr/scure-bip32 | `HDKey`}.
   * @param {number} params.account - BIP32 account index.
   * @param {number} [params.change] - Branch index (0 receive / 1 change).
   * @param {number | '*'} [params.index] - Address index or wildcard for ranged descriptors.
   * @param {string} [params.keyPath] - Full path suffix (`/change/index`) alternative.
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
    masterNode: BIP32InterfaceLike | ScureHDKeyLike;
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
    const originPath = `/${purpose}'/${coinTypeFromNetwork(network)}'/${account}'`;
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
