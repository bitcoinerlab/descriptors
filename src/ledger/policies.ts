// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { OutputInstance } from '../descriptors';
import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import type { HWWPolicy, HWWPolicyResolver } from '../hww/types';
import { fromHex, toHex } from 'uint8array-tools';
import {
  comparePolicies as compareWalletPolicies,
  policyFromOutput,
  policyFromPsbtInput,
  policyFromStandard,
  policyFromStore
} from '../hww/policies';
import { getMasterFingerprint, getXpub } from './client';
import type { LedgerPolicy, LedgerSession } from './types';

function ledgerPolicyToHWWPolicy(policy: LedgerPolicy): HWWPolicy {
  const registration =
    policy.policyId !== undefined || policy.policyHmac !== undefined
      ? {
          ...(policy.policyId !== undefined
            ? { id: fromHex(policy.policyId) }
            : {}),
          ...(policy.policyHmac !== undefined
            ? { hmac: fromHex(policy.policyHmac) }
            : {})
        }
      : undefined;

  return {
    descriptorTemplate: policy.descriptorTemplate,
    keyRoots: policy.keyRoots,
    ...(policy.name !== undefined ? { name: policy.name } : {}),
    ...(registration !== undefined ? { registration } : {})
  };
}

function hwwPolicyToLedgerPolicy(policy: HWWPolicy): LedgerPolicy {
  return {
    descriptorTemplate: policy.descriptorTemplate,
    keyRoots: policy.keyRoots,
    ...(policy.name !== undefined ? { name: policy.name } : {}),
    ...(policy.registration?.id !== undefined
      ? { policyId: toHex(policy.registration.id) }
      : {}),
    ...(policy.registration?.hmac !== undefined
      ? { policyHmac: toHex(policy.registration.hmac) }
      : {})
  };
}

function policyResolverFromSession(session: LedgerSession): HWWPolicyResolver {
  const knownPolicies = session.store.policies?.map(ledgerPolicyToHWWPolicy);
  return {
    Output: session.Output,
    network: session.network,
    ...(knownPolicies !== undefined ? { knownPolicies } : {}),
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    getAccountXpub: originPath => getXpub({ originPath, session })
  };
}

export async function ledgerPolicyFromPsbtInput({
  session,
  psbt,
  index
}: {
  session: LedgerSession;
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
}): Promise<LedgerPolicy | undefined> {
  const policy = await policyFromPsbtInput({
    policyResolver: policyResolverFromSession(session),
    psbt,
    index
  });
  return policy ? hwwPolicyToLedgerPolicy(policy) : undefined;
}

export async function ledgerPolicyFromOutput({
  output,
  session
}: {
  output: OutputInstance;
  session: LedgerSession;
}): Promise<{ descriptorTemplate: string; keyRoots: string[] } | null> {
  const policy = await policyFromOutput({
    output,
    policyResolver: policyResolverFromSession(session)
  });
  return policy
    ? {
        descriptorTemplate: policy.descriptorTemplate,
        keyRoots: policy.keyRoots
      }
    : null;
}

export async function ledgerPolicyFromStandard({
  output,
  session
}: {
  output: OutputInstance;
  session: LedgerSession;
}): Promise<LedgerPolicy | null> {
  const policy = await policyFromStandard({
    output,
    policyResolver: policyResolverFromSession(session)
  });
  return policy ? hwwPolicyToLedgerPolicy(policy) : null;
}

export function comparePolicies(policyA: LedgerPolicy, policyB: LedgerPolicy) {
  return compareWalletPolicies(
    ledgerPolicyToHWWPolicy(policyA),
    ledgerPolicyToHWWPolicy(policyB)
  );
}

export async function ledgerPolicyFromStore({
  output,
  session
}: {
  output: OutputInstance;
  session: LedgerSession;
}): Promise<LedgerPolicy | null> {
  const policy = await policyFromStore({
    output,
    policyResolver: policyResolverFromSession(session)
  });
  return policy ? hwwPolicyToLedgerPolicy(policy) : null;
}
