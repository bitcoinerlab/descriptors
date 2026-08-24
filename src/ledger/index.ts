/**
 * Ledger helpers shared by both preset packages.
 *
 * Bitcoinjs-ready usage:
 * ```ts
 * import { networks } from '@bitcoinerlab/descriptors';
 * import { registerPolicy, type Session } from '@bitcoinerlab/descriptors/ledger';
 * ```
 *
 * Scure-ready usage:
 * ```ts
 * import { networks } from '@bitcoinerlab/descriptors-scure';
 * import { registerPolicy, type Session } from '@bitcoinerlab/descriptors-scure/ledger';
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
 * Ledger checks these device-specific rules after deriving the shared policy.
 */

import { getMasterFingerprint, withLedgerManagerSession } from './client';
import { fromBase64, fromHex, toHex } from 'uint8array-tools';
// Used only to forward deprecated LedgerManager.Output. Remove in v4.
import type { OutputConstructor } from '../descriptors';
import {
  derivePolicyFromOutput,
  findKnownPolicy,
  isStandardPolicy,
  samePolicy
} from '../hww/policies';
import {
  assertDescriptorParams,
  assertLegacyMessageSignature,
  messageBytes,
  originPathFromKeyRoot,
  outputFromDescriptor,
  sampleOutputFromPolicyDescriptor
} from '../hww/helpers';
import type {
  LedgerClient,
  LedgerDefaultDescriptorTemplate,
  LedgerManager,
  LedgerPolicy,
  LedgerSession,
  LedgerStore
} from './types';
import { assertLedgerPolicySupported } from './policies';

export type { LedgerManager, LedgerState } from './types';

export {
  assertLedgerApp,
  getMasterFingerprint,
  getVersion,
  getXpub,
  getLedgerMasterFingerPrint,
  getLedgerXpub
} from './client';
export { keyExpression, keyExpressionLedger } from './keyExpressions';

type AddressDisplayParams = {
  descriptor: string;
  session: LedgerSession;
  change?: number;
  index?: number;
};

type MessageSigningParams = AddressDisplayParams & {
  message: string | Uint8Array;
};

/**
 * Registers a policy based on a provided descriptor.
 *
 * This function will:
 * 1. Store the policy in `store` inside the session.
 * 2. Avoid re-registering if the policy was previously registered.
 * 3. Skip registration if the policy is considered "standard".
 *
 * It's important to understand the nature of the Ledger policy being registered:
 * - While a descriptor might point to a specific output index of a particular
 *   change branch, the corresponding Ledger policy abstracts this and represents
 *   potential outputs for all receive and change indexes.
 * - This means that the registered Ledger policy is a generalized version of
 *   the descriptor, not assuming specific values for the key path.
 *
 * For a ranged descriptor, registration expands one deterministic sample using
 * index `0`. It also uses branch `0` when the branch is the receive/change range
 * `/**`. A fixed branch stays unchanged. The sample is used to parse and
 * validate the descriptor; it is not the policy sent to the device.
 *
 * Returns `undefined` because Ledger provides an app-owned registration
 * receipt, not a query for persistent policy storage on the device.
 *
 */
export async function registerPolicy({
  descriptor,
  session,
  name
}: {
  descriptor: string;
  session: LedgerSession;
  /** Name shown by the device for this policy. */
  name: string;
}): Promise<boolean | undefined> {
  return registerPolicyWithLegacyOutput({ descriptor, session, name });
}

/**
 * Threads the released `LedgerManager.Output` override into policy parsing.
 * Inline this body into `registerPolicy(...)` and remove the override in v4.
 *
 * @deprecated 3.x LedgerManager compatibility only.
 * @internal
 */
async function registerPolicyWithLegacyOutput({
  descriptor,
  session,
  name,
  legacyOutput
}: {
  descriptor: string;
  session: LedgerSession;
  name: string;
  /** @deprecated 3.x LedgerManager compatibility only. Remove in v4. */
  legacyOutput?: OutputConstructor;
}): Promise<boolean | undefined> {
  const { client, store, network } = session;
  const { WalletPolicy } = session.bitcoinApi;
  // Parse the policy through one deterministic output. The policy derived
  // below is generalized back to /** and is not limited to that sample.
  const sampleOutput = sampleOutputFromPolicyDescriptor({
    descriptor,
    network,
    ...(legacyOutput !== undefined ? { legacyOutput } : {})
  });
  const readMasterFingerprint = () => getMasterFingerprint({ session });
  const derivedPolicy = await derivePolicyFromOutput({
    output: sampleOutput,
    getMasterFingerprint: readMasterFingerprint
  });
  if (!derivedPolicy)
    throw new Error(`Error: output does not have a ledger input`);
  assertLedgerPolicySupported(derivedPolicy);
  const { descriptorTemplate, keyRoots } = derivedPolicy;
  if (isStandardPolicy({ descriptorTemplate, keyRoots, network }))
    return undefined;
  if (!store.policies) store.policies = [];
  const policy = findKnownPolicy({
    derivedPolicy,
    knownPolicies: store.policies
  }) as LedgerPolicy | null;
  if (policy) {
    if (policy.name && policy.name !== name)
      throw new Error(
        `Error: policy was already registered with a different name: ${policy.name}`
      );
    if (policy.name === name && policy.policyHmac) return undefined;
  }

  const walletPolicy = new WalletPolicy(name, descriptorTemplate, keyRoots);
  const [policyId, policyHmac] = await client.registerWallet(walletPolicy);
  const registeredPolicy: LedgerPolicy = {
    name,
    descriptorTemplate,
    keyRoots,
    policyId: toHex(policyId),
    policyHmac: toHex(policyHmac)
  };
  if (!policy) store.policies.push(registeredPolicy);
  else {
    const policyIndex = store.policies.findIndex(storedPolicy =>
      samePolicy(storedPolicy, policy)
    );
    if (policyIndex === -1)
      throw new Error(`Error: stored Ledger policy could not be replaced`);
    store.policies[policyIndex] = registeredPolicy;
  }
  return undefined;
}

/**
 * @deprecated Use `registerPolicy(...)` instead. Remove in v4 with
 * `LedgerManager` compatibility.
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
  await withLedgerManagerSession(ledgerManager, session =>
    registerPolicyWithLegacyOutput({
      descriptor,
      session,
      name: policyName,
      legacyOutput: ledgerManager.Output
    })
  );
}

export type Session = LedgerSession;
export type Store = LedgerStore;

export async function displayAddress({
  descriptor,
  session,
  change,
  index
}: AddressDisplayParams): Promise<string> {
  const { client } = session;
  const descriptorParams = {
    descriptor,
    ...(change !== undefined ? { change } : {}),
    ...(index !== undefined ? { index } : {})
  };
  assertDescriptorParams(descriptorParams);

  const { DefaultWalletPolicy, WalletPolicy } = session.bitcoinApi;
  const ledgerClient: LedgerClient = client;

  const output = outputFromDescriptor({
    ...descriptorParams,
    network: session.network
  });
  const derivedPolicy = await derivePolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (!derivedPolicy)
    throw new Error(`Error: output does not have a ledger input`);
  assertLedgerPolicySupported(derivedPolicy);
  if (
    isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network: session.network
    })
  ) {
    return ledgerClient.getWalletAddress(
      new DefaultWalletPolicy(
        derivedPolicy.descriptorTemplate as LedgerDefaultDescriptorTemplate,
        derivedPolicy.keyRoots[0]!
      ),
      null,
      derivedPolicy.change,
      derivedPolicy.index,
      true
    );
  }

  const policy = findKnownPolicy({
    derivedPolicy,
    ...(session.store.policies !== undefined
      ? { knownPolicies: session.store.policies }
      : {})
  }) as (LedgerPolicy & { change: number; index: number }) | null;
  if (!policy)
    throw new Error(`Ledger policy not registered; call registerPolicy first`);
  if (!policy.name || !policy.policyHmac)
    throw new Error(
      `Ledger policy missing registration; call registerPolicy first`
    );

  return ledgerClient.getWalletAddress(
    new WalletPolicy(policy.name, policy.descriptorTemplate, policy.keyRoots),
    fromHex(policy.policyHmac),
    policy.change,
    policy.index,
    true
  );
}

export async function signMessage({
  descriptor,
  session,
  message,
  change,
  index
}: MessageSigningParams): Promise<Uint8Array> {
  const { client } = session;
  const ledgerClient: LedgerClient = client;
  if (typeof ledgerClient.signMessage !== 'function')
    throw new Error(`Ledger client does not support message signing`);

  const descriptorParams = {
    descriptor,
    ...(change !== undefined ? { change } : {}),
    ...(index !== undefined ? { index } : {})
  };
  assertDescriptorParams(descriptorParams);

  const output = outputFromDescriptor({
    ...descriptorParams,
    network: session.network
  });
  const policy = await derivePolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (
    !policy ||
    !isStandardPolicy({
      descriptorTemplate: policy.descriptorTemplate,
      keyRoots: policy.keyRoots,
      network: session.network
    })
  )
    throw new Error(
      `Ledger message signing supports only standard single-key pkh, sh(wpkh), and wpkh descriptors`
    );
  if (
    policy.descriptorTemplate !== 'pkh(@0/**)' &&
    policy.descriptorTemplate !== 'sh(wpkh(@0/**))' &&
    policy.descriptorTemplate !== 'wpkh(@0/**)'
  ) {
    throw new Error(
      `Ledger message signing supports only standard single-key pkh, sh(wpkh), and wpkh descriptors`
    );
  }

  const originPath = originPathFromKeyRoot(policy.keyRoots[0] ?? '');
  if (!originPath) throw new Error(`Ledger key root missing origin path`);
  const signature = await ledgerClient.signMessage(
    messageBytes(message),
    `m${originPath}/${policy.change}/${policy.index}`
  );
  return assertLegacyMessageSignature(fromBase64(signature), 'Ledger');
}

export * as signers from './signers';
export * as scriptExpressions from './scriptExpressions';
export { connect } from './connectors';
