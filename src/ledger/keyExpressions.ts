// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { keyExpressionHWW } from '../hww/keyExpressions';
import { getMasterFingerprint, getXpub } from './client';
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
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  return keyExpressionHWW({
    keySource: {
      getMasterFingerprint: () => getMasterFingerprint({ session }),
      getAccountXpub: originPath => getXpub({ originPath, session })
    },
    originPath,
    keyPath,
    change,
    index
  });
}

/**
 * @deprecated Use `keyExpression(...)` from the Ledger entrypoint instead.
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
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  return keyExpression({
    session: {
      client: ledgerManager.ledgerClient,
      store: ledgerManager.ledgerState,
      Output: ledgerManager.Output,
      network: ledgerManager.network
    },
    originPath,
    keyPath,
    change,
    index
  });
}
