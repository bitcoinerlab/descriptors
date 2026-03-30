// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { toHex } from 'uint8array-tools';
import { assertChangeIndexKeyPath } from '../keyExpressions';
import {
  type LedgerManager,
  getLedgerMasterFingerPrint,
  getLedgerXpub
} from './index';

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
  assertChangeIndexKeyPath({ change, index, keyPath });

  const masterFingerprint = await getLedgerMasterFingerPrint({
    ledgerManager
  });
  const origin = `[${toHex(masterFingerprint)}${originPath}]`;
  const xpub = await getLedgerXpub({ originPath, ledgerManager });

  const keyRoot = `${origin}${xpub}`;
  if (keyPath !== undefined) return `${keyRoot}${keyPath}`;
  else return `${keyRoot}/${change}/${index}`;
}
