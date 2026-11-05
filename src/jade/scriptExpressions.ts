// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { coinTypeFromNetwork } from '../networkUtils';
import { assertStandardKeyPath } from '../scriptExpressions';
import { keyExpression } from './keyExpressions';
import type { JadeSession } from './types';

type StandardScriptExpressionParams = {
  session: JadeSession;
  account: number;
  keyPath?: string;
  change?: number;
  index?: number | '*';
};

function makeStandardExpression(purpose: number, scriptTemplate: string) {
  return async function standardScriptExpression({
    session,
    account,
    keyPath,
    change,
    index
  }: StandardScriptExpressionParams): Promise<string> {
    const originPath = `/${purpose}'/${coinTypeFromNetwork(session.network)}'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const key = await keyExpression({
      session,
      originPath,
      ...(keyPath !== undefined ? { keyPath } : {}),
      ...(change !== undefined ? { change } : {}),
      ...(index !== undefined ? { index } : {})
    });
    return scriptTemplate.replace('KEYEXPRESSION', key);
  };
}

export const pkh = makeStandardExpression(44, 'pkh(KEYEXPRESSION)');
export const shWpkh = makeStandardExpression(49, 'sh(wpkh(KEYEXPRESSION))');
export const wpkh = makeStandardExpression(84, 'wpkh(KEYEXPRESSION)');
export const tr = makeStandardExpression(86, 'tr(KEYEXPRESSION)');
