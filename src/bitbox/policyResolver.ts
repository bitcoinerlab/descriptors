// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { HWWPolicyResolver } from '../hww/types';
import { getMasterFingerprint, getXpub } from './client';
import type { BitBoxSession } from './types';

/** Builds the common HWW policy resolver for a BitBox session. */
export function policyResolverFromSession(
  session: BitBoxSession
): HWWPolicyResolver {
  const knownPolicies = session.store.policies;
  return {
    Output: session.Output,
    network: session.network,
    ...(knownPolicies !== undefined ? { knownPolicies } : {}),
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    getAccountXpub: originPath => getXpub({ originPath, session })
  };
}
