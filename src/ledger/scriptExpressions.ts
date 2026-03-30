// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { assertStandardKeyPath } from '../scriptExpressions';
import { coinTypeFromNetwork } from '../networkUtils';
import { type LedgerManager } from './index';
import { keyExpressionLedger } from './keyExpressions';

function standardExpressionsLedgerMaker(
  purpose: number,
  scriptTemplate: string
) {
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
    change?: number | undefined;
    index?: number | undefined | '*';
  }) {
    const { network } = ledgerManager;
    const originPath = `/${purpose}'/${coinTypeFromNetwork(network)}'/${account}'`;
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

export const pkhLedger = standardExpressionsLedgerMaker(
  44,
  'pkh(KEYEXPRESSION)'
);
export const shWpkhLedger = standardExpressionsLedgerMaker(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);
export const wpkhLedger = standardExpressionsLedgerMaker(
  84,
  'wpkh(KEYEXPRESSION)'
);
export const trLedger = standardExpressionsLedgerMaker(86, 'tr(KEYEXPRESSION)');
