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
 * All the conditions above are checked when deriving the common HWW policy.
 */

import { getMasterFingerprint, importAndValidateLedgerBitcoin } from './client';
import { fromBase64, fromHex, toHex } from 'uint8array-tools';
import {
  derivePolicyFromOutput,
  knownPolicyFromOutput,
  standardPolicyFromOutput
} from '../hww/policies';
import {
  assertLegacyMessageSignature,
  messageBytes,
  originPathFromKeyRoot,
  outputFromDescriptor
} from '../hww/helpers';
import {
  keyExpression as keyExpressionFromSession,
  keyExpressionLedger
} from './keyExpressions';
import type {
  LedgerClient,
  LedgerManager,
  LedgerPolicy,
  LedgerSession,
  LedgerState,
  LedgerStore
} from './types';

export type {
  LedgerClient,
  LedgerManager,
  LedgerPolicy,
  LedgerSession,
  LedgerState,
  LedgerStore
} from './types';

export {
  assertLedgerApp,
  getMasterFingerprint,
  getVersion,
  getXpub,
  getLedgerMasterFingerPrint,
  getLedgerXpub
} from './client';

type DefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';

type AddressDisplayParams = {
  descriptor: string;
  session: LedgerSession;
  change?: number;
  index: number;
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
 * It's important to understand the nature of the Ledger Policy being registered:
 * - While a descriptor might point to a specific output index of a particular change address,
 *   the corresponding Ledger Policy abstracts this and represents potential outputs for
 *   all addresses (both external and internal).
 * - This means that the registered Ledger Policy is a generalized version of the descriptor,
 *   not assuming specific values for the keyPath.
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
}): Promise<LedgerStore> {
  const { client, store, network } = session;
  const { WalletPolicy, AppClient } = (await importAndValidateLedgerBitcoin(
    client
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
  const output = outputFromDescriptor({
    descriptor,
    network,
    index: 0
  });
  const readMasterFingerprint = () => getMasterFingerprint({ session });
  if (
    await standardPolicyFromOutput({
      output,
      getMasterFingerprint: readMasterFingerprint
    })
  )
    return store;
  const result = await derivePolicyFromOutput({
    output,
    getMasterFingerprint: readMasterFingerprint
  });
  if (!result) throw new Error(`Error: output does not have a ledger input`);
  const { descriptorTemplate, keyRoots } = result;
  if (!store.policies) store.policies = [];
  const policy = (await knownPolicyFromOutput({
    output,
    getMasterFingerprint: readMasterFingerprint,
    knownPolicies: store.policies
  })) as LedgerPolicy | null;
  if (policy) {
    if (policy.name !== name)
      throw new Error(
        `Error: policy was already registered with a different name: ${policy.name}`
      );
  } else {
    const walletPolicy = new WalletPolicy(name, descriptorTemplate, keyRoots);
    const [policyId, policyHmac] = await client.registerWallet(walletPolicy);
    store.policies.push({
      name,
      descriptorTemplate,
      keyRoots,
      policyId: toHex(policyId),
      policyHmac: toHex(policyHmac)
    });
  }
  return store;
}

/**
 * @deprecated Use `registerPolicy(...)` instead.
 */
export async function registerWalletPolicy({
  descriptor,
  session,
  name
}: {
  descriptor: string;
  session: LedgerSession;
  /** Name shown by the device for this policy. */
  name: string;
}): Promise<LedgerStore> {
  return registerPolicy({ descriptor, session, name });
}

/**
 * @deprecated Use `registerPolicy(...)` instead.
 */
export async function registerWallet({
  descriptor,
  session,
  policyName
}: {
  descriptor: string;
  session: LedgerSession;
  /** Name shown by the device for this policy. */
  policyName: string;
}): Promise<LedgerStore> {
  return registerPolicy({ descriptor, session, name: policyName });
}

/**
 * @deprecated Use `registerPolicy(...)` instead.
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
  await registerPolicy({
    descriptor,
    session: {
      client: ledgerManager.ledgerClient,
      store: ledgerManager.ledgerState,
      network: ledgerManager.network
    },
    name: policyName
  });
}

export type Session = LedgerSession;
/** @deprecated Use `Session`. */
export type Manager = LedgerManager;
export type Store = LedgerStore;
/** @deprecated Use `Store`. */
export type State = LedgerState;

export async function keyExpression({
  session,
  originPath,
  keyPath,
  change,
  index
}: {
  session: LedgerSession;
  originPath: string;
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  return keyExpressionFromSession({
    session,
    originPath,
    keyPath,
    change,
    index
  });
}

export async function displayAddress({
  descriptor,
  session,
  change = 0,
  index
}: AddressDisplayParams): Promise<string> {
  const { client } = session;
  const { DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      client
    )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
  const ledgerClient: LedgerClient = client;

  const output = outputFromDescriptor({
    descriptor,
    network: session.network,
    change,
    index
  });
  const standardPolicy = await standardPolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (standardPolicy) {
    return ledgerClient.getWalletAddress(
      new DefaultWalletPolicy(
        standardPolicy.descriptorTemplate as DefaultDescriptorTemplate,
        standardPolicy.keyRoots[0]!
      ),
      null,
      change,
      index,
      true
    );
  }

  const policy = (await knownPolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    ...(session.store.policies !== undefined
      ? { knownPolicies: session.store.policies }
      : {})
  })) as LedgerPolicy | null;
  if (!policy)
    throw new Error(`Ledger policy not registered; call registerPolicy first`);
  if (!policy.name || !policy.policyHmac)
    throw new Error(
      `Ledger policy missing registration; call registerPolicy first`
    );

  return ledgerClient.getWalletAddress(
    new WalletPolicy(policy.name, policy.descriptorTemplate, policy.keyRoots),
    fromHex(policy.policyHmac),
    change,
    index,
    true
  );
}

export async function signMessage({
  descriptor,
  session,
  message,
  change = 0,
  index
}: MessageSigningParams): Promise<Uint8Array> {
  const { client } = session;
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    client
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
  const ledgerClient: LedgerClient = client;
  if (typeof ledgerClient.signMessage !== 'function')
    throw new Error(`Ledger client does not support message signing`);

  const output = outputFromDescriptor({
    descriptor,
    network: session.network,
    change,
    index
  });
  const policy = await standardPolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (!policy)
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
    `m${originPath}/${change}/${index}`
  );
  return assertLegacyMessageSignature(fromBase64(signature), 'Ledger');
}

export * as signers from './signers';
export { keyExpressionLedger };
export * as scriptExpressions from './scriptExpressions';
export * as connectors from './connectors';
