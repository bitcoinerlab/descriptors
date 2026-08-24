// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { originPathFromKeyRoot } from '../hww/helpers';
import type { HWWPolicy } from '../hww/policies';

/** Checks the key-origin rule required by the Ledger Bitcoin app. */
export function assertLedgerPolicySupported(policy: HWWPolicy): void {
  const originPaths = policy.keyRoots
    .map(originPathFromKeyRoot)
    .filter((originPath): originPath is string => originPath !== undefined);
  const uniqueOriginPaths = [...new Set(originPaths)];
  if (uniqueOriginPaths.length > 1) {
    throw new Error(
      `Ledger policies require every key with origin information to use the same origin path: ${uniqueOriginPaths.join(' !== ')}`
    );
  }
}
