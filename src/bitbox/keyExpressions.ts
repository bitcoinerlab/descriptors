// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { keyExpressionHWW } from '../hww/helpers';
import type { BitBoxSession } from './types';
import { getMasterFingerprint, getXpub } from './client';

export async function keyExpression({
  session,
  originPath,
  keyPath,
  change,
  index
}: {
  session: BitBoxSession;
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
