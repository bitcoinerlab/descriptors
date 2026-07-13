// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { keyExpressionHWW } from '../hww/helpers';
import {
  getMasterFingerprint,
  getXpub,
  sessionFromLedgerManager
} from './client';
import type { LedgerManager, LedgerSession } from './types';

export async function keyExpression({
  session,
  originPath,
  keyPath,
  change,
  index
}: {
  session: LedgerSession;
  originPath: string;
  change?: number;
  index?: number | '*';
  keyPath?: string;
}): Promise<string> {
  return keyExpressionHWW({
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    getAccountXpub: originPath => getXpub({ originPath, session }),
    originPath,
    ...(keyPath !== undefined ? { keyPath } : {}),
    ...(change !== undefined ? { change } : {}),
    ...(index !== undefined ? { index } : {})
  });
}

/**
 * @deprecated Use `keyExpression(...)` from the Ledger entrypoint instead.
 * Remove in v4 with `LedgerManager` compatibility.
 */
export async function keyExpressionLedger({
  ledgerManager,
  originPath,
  keyPath,
  change,
  index
}: {
  ledgerManager: LedgerManager;
  originPath: string;
  change?: number;
  index?: number | '*';
  keyPath?: string;
}): Promise<string> {
  return keyExpression({
    session: sessionFromLedgerManager(ledgerManager),
    originPath,
    ...(keyPath !== undefined ? { keyPath } : {}),
    ...(change !== undefined ? { change } : {}),
    ...(index !== undefined ? { index } : {})
  });
}
