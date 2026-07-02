// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { assertStandardKeyPath } from '../scriptExpressions';
import { coinTypeFromNetwork } from '../networkUtils';
import type { BitBoxManager } from './types';
import { keyExpressionBitBox } from './keyExpressions';

type StandardScriptExpressionBitBoxParams = {
  bitboxManager: BitBoxManager;
  account: number;
  keyPath?: string;
  change?: number | undefined;
  index?: number | undefined | '*';
};

function standardExpressionsBitBoxMaker(
  purpose: number,
  scriptTemplate: string
) {
  async function standardScriptExpressionBitBox({
    bitboxManager,
    account,
    keyPath,
    change,
    index
  }: StandardScriptExpressionBitBoxParams) {
    const { network } = bitboxManager;
    const originPath = `/${purpose}'/${coinTypeFromNetwork(network)}'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const keyExpression = await keyExpressionBitBox({
      bitboxManager,
      originPath,
      keyPath,
      change,
      index
    });

    return scriptTemplate.replace('KEYEXPRESSION', keyExpression);
  }
  return standardScriptExpressionBitBox;
}

export async function pkhBitBox(
  _params: StandardScriptExpressionBitBoxParams
): Promise<string> {
  throw new Error(
    `BitBox02 does not support top-level legacy p2pkh descriptors; use shWpkh, wpkh, or tr`
  );
}
export const shWpkhBitBox = standardExpressionsBitBoxMaker(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);
export const wpkhBitBox = standardExpressionsBitBoxMaker(
  84,
  'wpkh(KEYEXPRESSION)'
);
export const trBitBox = standardExpressionsBitBoxMaker(86, 'tr(KEYEXPRESSION)');

function bitboxParamsFromManager<Params extends { manager: BitBoxManager }>(
  params: Params
): Omit<Params, 'manager'> & { bitboxManager: BitBoxManager } {
  const { manager, ...rest } = params;
  return { ...rest, bitboxManager: manager };
}

export const pkh = (
  params: Omit<StandardScriptExpressionBitBoxParams, 'bitboxManager'> & {
    manager: BitBoxManager;
  }
) => pkhBitBox(bitboxParamsFromManager(params));

export const shWpkh = (
  params: Omit<Parameters<typeof shWpkhBitBox>[0], 'bitboxManager'> & {
    manager: BitBoxManager;
  }
) => shWpkhBitBox(bitboxParamsFromManager(params));

export const wpkh = (
  params: Omit<Parameters<typeof wpkhBitBox>[0], 'bitboxManager'> & {
    manager: BitBoxManager;
  }
) => wpkhBitBox(bitboxParamsFromManager(params));

export const tr = (
  params: Omit<Parameters<typeof trBitBox>[0], 'bitboxManager'> & {
    manager: BitBoxManager;
  }
) => trBitBox(bitboxParamsFromManager(params));
