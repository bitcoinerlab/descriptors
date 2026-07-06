// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { toHex } from 'uint8array-tools';
import { assertChangeIndexKeyPath } from '../keyExpressions';
import type { HWWKeySource } from './types';

export async function keyExpressionHWW({
  keySource,
  originPath,
  keyPath,
  change,
  index
}: {
  keySource: HWWKeySource;
  originPath: string;
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  assertChangeIndexKeyPath({ change, index, keyPath });

  const masterFingerprint = await keySource.getMasterFingerprint();
  const origin = `[${toHex(masterFingerprint)}${originPath}]`;
  const xpub = await keySource.getAccountXpub(originPath);

  const keyRoot = `${origin}${xpub}`;
  if (keyPath !== undefined) return `${keyRoot}${keyPath}`;
  else return `${keyRoot}/${change}/${index}`;
}
