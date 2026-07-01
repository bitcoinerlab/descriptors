// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { OutputInstance } from '../descriptors';
import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import type { HardwareWalletPolicyManager, WalletPolicy } from '../hww/types';
import {
  comparePolicies as compareWalletPolicies,
  policyFromOutput,
  policyFromPsbtInput,
  policyFromStandard,
  policyFromState
} from '../hww/policies';
import { getLedgerMasterFingerPrint, getLedgerXpub } from './client';
import type { LedgerManager } from './index';

export type LedgerPolicy = {
  policyName?: string;
  ledgerTemplate: string;
  keyRoots: string[];
  policyId?: Uint8Array;
  policyHmac?: Uint8Array;
};

function ledgerPolicyToWalletPolicy(policy: LedgerPolicy): WalletPolicy {
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

function walletPolicyToLedgerPolicy(policy: WalletPolicy): LedgerPolicy {
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

function hwwManagerFromLedgerManager(
  ledgerManager: LedgerManager
): HardwareWalletPolicyManager {
  const policies = ledgerManager.ledgerState.policies?.map(
    ledgerPolicyToWalletPolicy
  );
  return {
    Output: ledgerManager.Output,
    network: ledgerManager.network,
    ...(policies !== undefined ? { policies } : {}),
    getMasterFingerprint: () => getLedgerMasterFingerPrint({ ledgerManager }),
    getXpub: originPath => getLedgerXpub({ originPath, ledgerManager })
  };
}

export async function ledgerPolicyFromPsbtInput({
  ledgerManager,
  psbt,
  index
}: {
  ledgerManager: LedgerManager;
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
}): Promise<LedgerPolicy | undefined> {
  const policy = await policyFromPsbtInput({
    hwwManager: hwwManagerFromLedgerManager(ledgerManager),
    psbt,
    index
  });
  return policy ? walletPolicyToLedgerPolicy(policy) : undefined;
}

export async function ledgerPolicyFromOutput({
  output,
  ledgerManager
}: {
  output: OutputInstance;
  ledgerManager: LedgerManager;
}): Promise<{ ledgerTemplate: string; keyRoots: string[] } | null> {
  const policy = await policyFromOutput({
    output,
    hwwManager: hwwManagerFromLedgerManager(ledgerManager)
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
  ledgerManager
}: {
  output: OutputInstance;
  ledgerManager: LedgerManager;
}): Promise<LedgerPolicy | null> {
  const policy = await policyFromStandard({
    output,
    hwwManager: hwwManagerFromLedgerManager(ledgerManager)
  });
  return policy ? walletPolicyToLedgerPolicy(policy) : null;
}

export function comparePolicies(policyA: LedgerPolicy, policyB: LedgerPolicy) {
  return compareWalletPolicies(
    ledgerPolicyToWalletPolicy(policyA),
    ledgerPolicyToWalletPolicy(policyB)
  );
}

export async function ledgerPolicyFromState({
  output,
  ledgerManager
}: {
  output: OutputInstance;
  ledgerManager: LedgerManager;
}): Promise<LedgerPolicy | null> {
  const policy = await policyFromState({
    output,
    hwwManager: hwwManagerFromLedgerManager(ledgerManager)
  });
  return policy ? walletPolicyToLedgerPolicy(policy) : null;
}
