// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { keyExpressionHardwareWallet } from '../hww/keyExpressions';
import {
  type LedgerManager,
  getLedgerMasterFingerPrint,
  getLedgerXpub
} from './index';

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
  return keyExpressionHardwareWallet({
    hwwManager: {
      Output: ledgerManager.Output,
      network: ledgerManager.network,
      getMasterFingerprint: () => getLedgerMasterFingerPrint({ ledgerManager }),
      getXpub: originPath => getLedgerXpub({ originPath, ledgerManager })
    },
    originPath,
    keyPath,
    change,
    index
  });
}
