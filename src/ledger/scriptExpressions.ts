// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { assertStandardKeyPath } from '../scriptExpressions';
import { coinTypeFromNetwork } from '../networkUtils';
import { keyExpression } from './keyExpressions';
import { sessionFromLedgerManager } from './client';
import type { LedgerManager, LedgerSession } from './types';

type StandardScriptExpressionParams = {
  session: LedgerSession;
  account: number;
  keyPath?: string;
  change?: number;
  index?: number | '*';
};

type DeprecatedLedgerStandardScriptExpressionParams = Omit<
  StandardScriptExpressionParams,
  'session'
> & {
  ledgerManager: LedgerManager;
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

export const pkh = makeStandardExpression(44, 'pkh(KEYEXPRESSION)');
export const shWpkh = makeStandardExpression(49, 'sh(wpkh(KEYEXPRESSION))');
export const wpkh = makeStandardExpression(84, 'wpkh(KEYEXPRESSION)');
export const tr = makeStandardExpression(86, 'tr(KEYEXPRESSION)');

/** @deprecated Use the session-based standard script expressions instead. */
function makeStandardExpressionLedger(purpose: number, scriptTemplate: string) {
  const standardScriptExpression = makeStandardExpression(
    purpose,
    scriptTemplate
  );

  return async function standardScriptExpressionLedger({
    ledgerManager,
    ...params
  }: DeprecatedLedgerStandardScriptExpressionParams) {
    return standardScriptExpression({
      ...params,
      session: sessionFromLedgerManager(ledgerManager)
    });
  };
}

/** @deprecated Use `pkh(...)` instead. */
export const pkhLedger = makeStandardExpressionLedger(44, 'pkh(KEYEXPRESSION)');

/** @deprecated Use `shWpkh(...)` instead. */
export const shWpkhLedger = makeStandardExpressionLedger(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);

/** @deprecated Use `wpkh(...)` instead. */
export const wpkhLedger = makeStandardExpressionLedger(
  84,
  'wpkh(KEYEXPRESSION)'
);

/** @deprecated Use `tr(...)` instead. */
export const trLedger = makeStandardExpressionLedger(86, 'tr(KEYEXPRESSION)');
