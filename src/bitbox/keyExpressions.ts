// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { keyExpressionHardwareWallet } from '../hww/keyExpressions';
import type { BitBoxManager } from './types';
import { getBitBoxMasterFingerprint, getBitBoxXpub } from './client';

export async function keyExpressionBitBox({
  bitboxManager,
  originPath,
  keyPath,
  change,
  index
}: {
  bitboxManager: BitBoxManager;
  originPath: string;
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  return keyExpressionHardwareWallet({
    hwwManager: {
      Output: bitboxManager.Output,
      network: bitboxManager.network,
      getMasterFingerprint: () => getBitBoxMasterFingerprint({ bitboxManager }),
      getXpub: originPath => getBitBoxXpub({ originPath, bitboxManager })
    },
    originPath,
    keyPath,
    change,
    index
  });
}
