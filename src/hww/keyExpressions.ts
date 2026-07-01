// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { toHex } from 'uint8array-tools';
import { assertChangeIndexKeyPath } from '../keyExpressions';
import type { HardwareWalletPolicyManager } from './types';

export async function keyExpressionHardwareWallet({
  hwwManager,
  originPath,
  keyPath,
  change,
  index
}: {
  hwwManager: HardwareWalletPolicyManager;
  originPath: string;
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  assertChangeIndexKeyPath({ change, index, keyPath });

  const masterFingerprint = await hwwManager.getMasterFingerprint();
  const origin = `[${toHex(masterFingerprint)}${originPath}]`;
  const xpub = await hwwManager.getXpub(originPath);

  const keyRoot = `${origin}${xpub}`;
  if (keyPath !== undefined) return `${keyRoot}${keyPath}`;
  else return `${keyRoot}/${change}/${index}`;
}
