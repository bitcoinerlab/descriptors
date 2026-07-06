/**
 * Ledger helpers shared by both preset packages.
 *
 * Bitcoinjs-ready usage:
 * ```ts
 * import { Output, networks } from '@bitcoinerlab/descriptors';
 * import { registerWallet, type Session } from '@bitcoinerlab/descriptors/ledger';
 * ```
 *
 * Scure-ready usage:
 * ```ts
 * import { Output, networks } from '@bitcoinerlab/descriptors-scure';
 * import { registerWallet, type Session } from '@bitcoinerlab/descriptors-scure/ledger';
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

import { importAndValidateLedgerBitcoin } from './client';
import { fromBase64, fromUtf8 } from 'uint8array-tools';
import {
  ledgerPolicyFromOutput,
  ledgerPolicyFromStandard,
  ledgerPolicyFromState
} from './policies';
import {
  keyExpression as keyExpressionFromSession,
  keyExpressionLedger
} from './keyExpressions';
import type {
  LedgerClient,
  LedgerManager,
  LedgerSession,
  LedgerState
} from './types';

export type {
  LedgerClient,
  LedgerManager,
  LedgerPartialSignature,
  LedgerPolicy,
  LedgerSession,
  LedgerState,
  LedgerWalletPolicyLike
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

export type AddressDisplayParams = {
  descriptor: string;
  session: LedgerSession;
  change?: number;
  index: number;
};

type MessageSigningParams = AddressDisplayParams & {
  message: string | Uint8Array;
};

function outputFromDescriptor({
  descriptor,
  session,
  change,
  index
}: AddressDisplayParams) {
  const { Output, network } = session;
  return new Output({
    descriptor,
    ...(descriptor.includes('*') ? { index } : {}),
    ...(change !== undefined ? { change } : {}),
    network
  });
}

function originPathFromKeyRoot(keyRoot: string): string | undefined {
  return keyRoot.match(/^\[[0-9a-fA-F]{8}([^\]]*)\]/)?.[1];
}

function assertLegacyMessageSignature(
  signature: Uint8Array,
  device: string
): Uint8Array {
  if (signature.length !== 65)
    throw new Error(`${device} client returned an invalid message signature`);
  return signature;
}

function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === 'string' ? fromUtf8(message) : message;
}

/**
 * Registers a policy based on a provided descriptor.
 *
 * This function will:
 * 1. Store the policy in `state` inside the session.
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
export async function registerWallet({
  descriptor,
  session,
  policyName
}: {
  descriptor: string;
  session: LedgerSession;
  /** The Name we want to assign to this specific policy */
  policyName: string;
}): Promise<void> {
  const { client, state, network, Output } = session;
  const { WalletPolicy, AppClient } = (await importAndValidateLedgerBitcoin(
    client
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
  const output = new Output({
    descriptor,
    ...(descriptor.includes('*') ? { index: 0 } : {}),
    network
  });
  if (await ledgerPolicyFromStandard({ output, session })) return;
  const result = await ledgerPolicyFromOutput({ output, session });
  if (await ledgerPolicyFromStandard({ output, session })) return;
  if (!result) throw new Error(`Error: output does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (!state.policies) state.policies = [];
  let walletPolicy, policyHmac;
  const policy = await ledgerPolicyFromState({ output, session });
  if (policy) {
    if (policy.policyName !== policyName)
      throw new Error(
        `Error: policy was already registered with a different name: ${policy.policyName}`
      );
  } else {
    walletPolicy = new WalletPolicy(policyName, ledgerTemplate, keyRoots);
    let policyId;
    [policyId, policyHmac] = await client.registerWallet(walletPolicy);
    state.policies.push({
      policyName,
      ledgerTemplate,
      keyRoots,
      policyId,
      policyHmac
    });
  }
}

/**
 * @deprecated Use `registerWallet(...)` instead.
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
  return registerWallet({
    descriptor,
    session: {
      client: ledgerManager.ledgerClient,
      state: ledgerManager.ledgerState,
      Output: ledgerManager.Output,
      network: ledgerManager.network
    },
    policyName
  });
}

export type Session = LedgerSession;
/** @deprecated Use `Session`. */
export type Manager = LedgerManager;
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

  const output = outputFromDescriptor({ descriptor, session, change, index });
  const standardPolicy = await ledgerPolicyFromStandard({ output, session });
  if (standardPolicy) {
    return ledgerClient.getWalletAddress(
      new DefaultWalletPolicy(
        standardPolicy.ledgerTemplate as DefaultDescriptorTemplate,
        standardPolicy.keyRoots[0]!
      ),
      null,
      change,
      index,
      true
    );
  }

  const policy = await ledgerPolicyFromState({ output, session });
  if (!policy)
    throw new Error(`Ledger policy not registered; call registerWallet first`);
  if (!policy.policyName || !policy.policyHmac)
    throw new Error(
      `Ledger policy missing registration; call registerWallet first`
    );

  return ledgerClient.getWalletAddress(
    new WalletPolicy(policy.policyName, policy.ledgerTemplate, policy.keyRoots),
    policy.policyHmac,
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

  const output = outputFromDescriptor({ descriptor, session, change, index });
  const policy = await ledgerPolicyFromStandard({ output, session });
  if (!policy)
    throw new Error(
      `Ledger message signing supports only standard single-key pkh, sh(wpkh), and wpkh descriptors`
    );
  if (
    policy.ledgerTemplate !== 'pkh(@0/**)' &&
    policy.ledgerTemplate !== 'sh(wpkh(@0/**))' &&
    policy.ledgerTemplate !== 'wpkh(@0/**)'
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
