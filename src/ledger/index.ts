/**
 * Ledger helpers shared by both preset packages.
 *
 * Bitcoinjs-ready usage:
 * ```ts
 * import { Output, networks } from '@bitcoinerlab/descriptors';
 * import { registerLedgerWallet, type LedgerManager } from '@bitcoinerlab/descriptors/ledger';
 * ```
 *
 * Scure-ready usage:
 * ```ts
 * import { Output, networks } from '@bitcoinerlab/descriptors-scure';
 * import { registerLedgerWallet, type LedgerManager } from '@bitcoinerlab/descriptors-scure/ledger';
 * ```
 *
 * @module ledger
 */

// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/*
 * Notes on Ledger implementation:
 *
 * Ledger assumes as external all keyRoots that do not have origin information.
 *
 * Some known Ledger Limitations (based on my tests as of Febr 2023):
 *
 * 1) All keyExpressions must be expanded into @i. In other words,
 * this template is not valid:
 * wsh(and_v(v:pk(03ed0b41d808b012b3a77dd7f6a30c4180dfbcab604133d90ce7593ec7f3e4037b),and_v(v:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333),and_v(and_v(v:pk(@0/**),v:pk(@1/**)),older(5)))))
 * (note the fixed 03ed0b41d808b012b3a77dd7f6a30c4180dfbcab604133d90ce7593ec7f3e4037b pubkey)
 *
 * 2) All elements in the keyRoot vector must be xpub-type (no xprv-type, no pubkey-type, ...)
 *
 * 3) All originPaths of the expressions in the keyRoot vector must be the same.
 * On the other hand, an empty originPath is permitted for external keys.
 *
 * 4) Since all originPaths must be the same and originPaths for the Ledger are
 * necessary, a Ledger device can only sign at most 1 key per policy and input.
 *
 * All the conditions above are checked in function ledgerPolicyFromOutput.
 */

import { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import { importAndValidateLedgerBitcoin } from './client';
import {
  ledgerPolicyFromOutput,
  ledgerPolicyFromStandard,
  ledgerPolicyFromState
} from './policies';

/**
 * Ledger devices operate in a state-less manner. Therefore, policy information
 * needs to be maintained in a separate data structure, `ledgerState`. For optimization,
 * `ledgerState` also stores cached xpubs and the masterFingerprint.
 */
export type LedgerState = {
  masterFingerprint?: Uint8Array;
  policies?: {
    policyName?: string;
    ledgerTemplate: string;
    keyRoots: string[];
    policyId?: Uint8Array;
    policyHmac?: Uint8Array;
  }[];
  xpubs?: { [key: string]: string };
};

/**
 * State and helpers needed for Ledger integration.
 *
 * Pass the pre-bound `Output` constructor from the package you are using:
 * - `@bitcoinerlab/descriptors`
 * - `@bitcoinerlab/descriptors-scure`
 */
export type LedgerManager = {
  /** Ledger Bitcoin app client instance. */
  ledgerClient: unknown;
  /** Mutable cache for fingerprints, xpubs and registered policies. */
  ledgerState: LedgerState;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
};

export {
  assertLedgerApp,
  getLedgerMasterFingerPrint,
  getLedgerXpub
} from './client';

/**
 * Registers a policy based on a provided descriptor.
 *
 * This function will:
 * 1. Store the policy in `ledgerState` inside the `ledgerManager`.
 * 2. Avoid re-registering if the policy was previously registered.
 * 3. Skip registration if the policy is considered "standard".
 *
 * It's important to understand the nature of the Ledger Policy being registered:
 * - While a descriptor might point to a specific output index of a particular change address,
 *   the corresponding Ledger Policy abstracts this and represents potential outputs for
 *   all addresses (both external and internal).
 * - This means that the registered Ledger Policy is a generalized version of the descriptor,
 *   not assuming specific values for the keyPath.
 */
export async function registerLedgerWallet({
  descriptor,
  ledgerManager,
  policyName
}: {
  descriptor: string;
  ledgerManager: LedgerManager;
  /** The Name we want to assign to this specific policy */
  policyName: string;
}): Promise<void> {
  const { ledgerClient, ledgerState, network, Output } = ledgerManager;
  const { WalletPolicy, AppClient } = (await importAndValidateLedgerBitcoin(
    ledgerClient
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);
  const output = new Output({
    descriptor,
    ...(descriptor.includes('*') ? { index: 0 } : {}),
    network
  });
  if (await ledgerPolicyFromStandard({ output, ledgerManager })) return;
  const result = await ledgerPolicyFromOutput({ output, ledgerManager });
  if (await ledgerPolicyFromStandard({ output, ledgerManager })) return;
  if (!result) throw new Error(`Error: output does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (!ledgerState.policies) ledgerState.policies = [];
  let walletPolicy, policyHmac;
  const policy = await ledgerPolicyFromState({ output, ledgerManager });
  if (policy) {
    if (policy.policyName !== policyName)
      throw new Error(
        `Error: policy was already registered with a different name: ${policy.policyName}`
      );
  } else {
    walletPolicy = new WalletPolicy(policyName, ledgerTemplate, keyRoots);
    let policyId;
    [policyId, policyHmac] = await ledgerClient.registerWallet(walletPolicy);
    ledgerState.policies.push({
      policyName,
      ledgerTemplate,
      keyRoots,
      policyId,
      policyHmac
    });
  }
}

export * as signers from './signers';
export { keyExpressionLedger } from './keyExpressions';
export * as scriptExpressions from './scriptExpressions';
