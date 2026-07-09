// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { assertStandardKeyPath } from '../scriptExpressions';
import { coinTypeFromNetwork } from '../networkUtils';
import type { BitBoxSession } from './types';
import { keyExpression } from './keyExpressions';

type StandardScriptExpressionParams = {
  session: BitBoxSession;
  account: number;
  keyPath?: string;
  change?: number;
  index?: number | '*';
};

function makeStandardExpression(purpose: number, scriptTemplate: string) {
  async function standardScriptExpression({
    session,
    account,
    keyPath,
    change,
    index
  }: StandardScriptExpressionParams) {
    const { network } = session;
    const originPath = `/${purpose}'/${coinTypeFromNetwork(network)}'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const key = await keyExpression({
      session,
      originPath,
      ...(keyPath !== undefined ? { keyPath } : {}),
      ...(change !== undefined ? { change } : {}),
      ...(index !== undefined ? { index } : {})
    });

    return scriptTemplate.replace('KEYEXPRESSION', key);
  }
  return standardScriptExpression;
}

export async function pkh(
  _params: StandardScriptExpressionParams
): Promise<string> {
  throw new Error(
    `BitBox02 does not support top-level legacy p2pkh descriptors; use shWpkh, wpkh, or tr`
  );
}
export const shWpkh = makeStandardExpression(49, 'sh(wpkh(KEYEXPRESSION))');
export const wpkh = makeStandardExpression(84, 'wpkh(KEYEXPRESSION)');
export const tr = makeStandardExpression(86, 'tr(KEYEXPRESSION)');
