// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { keyExpressionHWW } from '../hww/helpers';
import { getMasterFingerprint, getXpub } from './client';
import type { JadeSession } from './types';

export async function keyExpression({
  session,
  originPath,
  keyPath,
  change,
  index
}: {
  session: JadeSession;
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
