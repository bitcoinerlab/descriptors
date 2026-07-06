// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { OutputInstance } from '../descriptors';
import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import type { HWWPolicy, HWWPolicyResolver } from '../hww/types';
import {
  comparePolicies as compareWalletPolicies,
  policyFromOutput,
  policyFromPsbtInput,
  policyFromStandard,
  policyFromState
} from '../hww/policies';
import { getMasterFingerprint, getXpub } from './client';
import type { LedgerPolicy, LedgerSession } from './types';

function ledgerPolicyToHWWPolicy(policy: LedgerPolicy): HWWPolicy {
  const registration =
    policy.policyId !== undefined || policy.policyHmac !== undefined
      ? {
          ...(policy.policyId !== undefined ? { id: policy.policyId } : {}),
          ...(policy.policyHmac !== undefined
            ? { hmac: policy.policyHmac }
            : {})
        }
      : undefined;

  return {
    descriptorTemplate: policy.ledgerTemplate,
    keyRoots: policy.keyRoots,
    ...(policy.policyName !== undefined
      ? { policyName: policy.policyName }
      : {}),
    ...(registration !== undefined ? { registration } : {})
  };
}

function hwwPolicyToLedgerPolicy(policy: HWWPolicy): LedgerPolicy {
  return {
    ledgerTemplate: policy.descriptorTemplate,
    keyRoots: policy.keyRoots,
    ...(policy.policyName !== undefined
      ? { policyName: policy.policyName }
      : {}),
    ...(policy.registration?.id !== undefined
      ? { policyId: policy.registration.id }
      : {}),
    ...(policy.registration?.hmac !== undefined
      ? { policyHmac: policy.registration.hmac }
      : {})
  };
}

function policyResolverFromSession(session: LedgerSession): HWWPolicyResolver {
  const knownPolicies = session.state.policies?.map(ledgerPolicyToHWWPolicy);
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
}): Promise<{ ledgerTemplate: string; keyRoots: string[] } | null> {
  const policy = await policyFromOutput({
    output,
    policyResolver: policyResolverFromSession(session)
  });
  return policy
    ? {
        ledgerTemplate: policy.descriptorTemplate,
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

export async function ledgerPolicyFromState({
  output,
  session
}: {
  output: OutputInstance;
  session: LedgerSession;
}): Promise<LedgerPolicy | null> {
  const policy = await policyFromState({
    output,
    policyResolver: policyResolverFromSession(session)
  });
  return policy ? hwwPolicyToLedgerPolicy(policy) : null;
}
