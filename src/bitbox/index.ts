/**
 * BitBox helpers shared by both preset packages.
 *
 * This entrypoint does not import `bitbox-api` directly. Pass a connected and
 * paired BitBox client from whichever transport/runtime integration your app
 * uses.
 *
 * @module bitbox
 */

// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  assertPolicyCanDerive,
  policyFromStandard,
  policyFromState,
  addressKeypathFromPolicy,
  scriptConfigFromMultisigAccount,
  scriptConfigFromPolicy
} from './policies';
import { apiNetwork, simpleType } from './client';
import { fromUtf8 } from 'uint8array-tools';
import type { BitBoxPolicy, BitBoxSession, BitBoxState } from './types';

export type {
  BitBoxApiNetwork,
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxKeyOriginInfo,
  BitBoxKeypath,
  BitBoxMultisigAccount,
  BitBoxMultisigScriptConfig,
  BitBoxMultisigScriptType,
  BitBoxPolicy,
  BitBoxPolicyScriptConfig,
  BitBoxRegisterXPubType,
  BitBoxScriptConfig,
  BitBoxScriptConfigWithKeypath,
  BitBoxSession,
  BitBoxSimpleType,
  BitBoxState,
  BitBoxXPubType
} from './types';

export { registerWallet } from './policies';
export { getMasterFingerprint, getVersion, getXpub } from './client';
export { keyExpression } from './keyExpressions';
export * as scriptExpressions from './scriptExpressions';
export * as signers from './signers';
export * as connectors from './connectors';

export type Session = BitBoxSession;
export type State = BitBoxState;

export type AddressDisplayParams = {
  descriptor: string;
  session: BitBoxSession;
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

function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === 'string' ? fromUtf8(message) : message;
}

function assertLegacyMessageSignature(
  signature: Uint8Array,
  device: string
): Uint8Array {
  if (signature.length !== 65)
    throw new Error(`${device} client returned an invalid message signature`);
  return signature;
}

function keyRootOriginPath(keyRoot: string): string | undefined {
  return keyRoot.match(/^\[[0-9a-fA-F]{8}([^\]]*)\]/)?.[1];
}

async function displayStandardAddress({
  policy,
  session,
  change,
  index
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
  change: number;
  index: number;
}) {
  const { client } = session;
  const originPath = keyRootOriginPath(policy.keyRoots[0] ?? '');
  if (!originPath) throw new Error(`BitBox02 key root missing origin path`);
  return client.btcAddress(
    apiNetwork(session),
    `m${originPath}/${change}/${index}`,
    {
      simpleType: simpleType({
        descriptorTemplate: policy.descriptorTemplate,
        session
      })
    },
    true
  );
}

async function displayMultisigAddress({
  policy,
  session,
  change,
  index
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
  change: number;
  index: number;
}) {
  const { client } = session;
  const account = policy.account;
  if (!account)
    throw new Error(`BitBox policy missing account; call registerWallet first`);
  return client.btcAddress(
    apiNetwork(session),
    `${account.keypathAccount}/${change}/${index}`,
    scriptConfigFromMultisigAccount(account),
    true
  );
}

async function displayPolicyAddress({
  policy,
  session,
  change,
  index
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
  change: number;
  index: number;
}) {
  assertPolicyCanDerive(policy);
  return session.client.btcAddress(
    apiNetwork(session),
    addressKeypathFromPolicy({ policy, session, change, index }),
    scriptConfigFromPolicy({ policy, session }),
    true
  );
}

export async function displayAddress({
  descriptor,
  session,
  change = 0,
  index
}: AddressDisplayParams): Promise<string | void> {
  const output = outputFromDescriptor({ descriptor, session, change, index });
  const standardPolicy = await policyFromStandard({
    output,
    session
  });
  if (standardPolicy)
    return displayStandardAddress({
      policy: standardPolicy,
      session,
      change,
      index
    });

  const policy = await policyFromState({ output, session });
  if (!policy)
    throw new Error(`BitBox policy not registered; call registerWallet first`);
  return policy.account
    ? displayMultisigAddress({ policy, session, change, index })
    : displayPolicyAddress({ policy, session, change, index });
}

export async function signMessage({
  descriptor,
  session,
  message,
  change = 0,
  index
}: MessageSigningParams): Promise<Uint8Array> {
  const { client } = session;
  if (typeof client.btcSignMessage !== 'function')
    throw new Error(`BitBox client does not support message signing`);

  const output = outputFromDescriptor({ descriptor, session, change, index });
  const policy = await policyFromStandard({ output, session });
  if (!policy)
    throw new Error(
      `BitBox message signing supports only standard single-key sh(wpkh) and wpkh descriptors`
    );
  if (policy.descriptorTemplate === 'pkh(@0/**)') {
    throw new Error(
      `BitBox02 does not support top-level legacy p2pkh descriptors; use shWpkh, wpkh, or tr`
    );
  }
  if (policy.descriptorTemplate === 'tr(@0/**)')
    throw new Error(`BitBox02 does not support Taproot message signing`);
  if (
    policy.descriptorTemplate !== 'sh(wpkh(@0/**))' &&
    policy.descriptorTemplate !== 'wpkh(@0/**)'
  ) {
    throw new Error(
      `BitBox message signing supports only standard single-key sh(wpkh) and wpkh descriptors`
    );
  }

  const result = await client.btcSignMessage(
    apiNetwork(session),
    {
      scriptConfig: scriptConfigFromPolicy({ policy, session }),
      keypath: addressKeypathFromPolicy({ policy, session, change, index })
    },
    messageBytes(message)
  );
  return assertLegacyMessageSignature(result.electrumSig65, 'BitBox');
}
