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
  addressKeypathFromPolicy,
  scriptConfigForRegistration,
  scriptConfigFromPolicy
} from './scriptConfig';
import {
  derivePolicyFromOutput,
  knownPolicyFromOutput,
  standardPolicyFromOutput
} from '../hww/policies';
import {
  assertDescriptorParams,
  assertLegacyMessageSignature,
  messageBytes,
  originPathFromKeyRoot,
  outputFromDescriptor
} from '../hww/helpers';
import { apiNetwork, getMasterFingerprint, simpleType } from './client';
import type { BitBoxPolicy, BitBoxSession, BitBoxStore } from './types';

export type {
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxPolicy,
  BitBoxSession,
  BitBoxStore
} from './types';

export { getMasterFingerprint, getVersion, getXpub } from './client';
export { keyExpression } from './keyExpressions';
export * as scriptExpressions from './scriptExpressions';
export * as signers from './signers';
export * as connectors from './connectors';

export type Session = BitBoxSession;
export type Store = BitBoxStore;

type AddressDisplayParams = {
  descriptor: string;
  session: BitBoxSession;
  change?: number;
  index?: number;
};

type MessageSigningParams = AddressDisplayParams & {
  message: string | Uint8Array;
};

/**
 * Registers a non-standard descriptor policy with BitBox when needed.
 *
 * BitBox returns no Ledger-style id or HMAC. The device remembers the approved
 * script config internally, while this function stores the descriptor policy in
 * the app-owned JSON store so address display and PSBT signing can rebuild the
 * same script config later.
 */
export async function registerPolicy({
  descriptor,
  session,
  name
}: {
  descriptor: string;
  session: BitBoxSession;
  /** Name shown by the device for this policy. */
  name: string;
}): Promise<BitBoxStore> {
  const { client, store, network } = session;
  const output = outputFromDescriptor({
    descriptor,
    network,
    ...(descriptor.includes('/<') ? { change: 0 } : {}),
    index: 0
  });
  const readMasterFingerprint = () => getMasterFingerprint({ session });

  const standardPolicy = await standardPolicyFromOutput({
    output,
    getMasterFingerprint: readMasterFingerprint
  });
  if (standardPolicy) {
    simpleType({
      descriptorTemplate: standardPolicy.descriptorTemplate,
      session
    });
    return store;
  }

  const result = await derivePolicyFromOutput({
    output,
    getMasterFingerprint: readMasterFingerprint
  });
  if (!result) throw new Error(`Error: output does not have a BitBox02 input`);
  if (!store.policies) store.policies = [];

  const existingPolicy = await knownPolicyFromOutput({
    output,
    getMasterFingerprint: readMasterFingerprint,
    knownPolicies: store.policies
  });
  if (existingPolicy) {
    if (existingPolicy.name !== name)
      throw new Error(
        `Error: policy was already registered with a different name: ${existingPolicy.name}`
      );
    return store;
  }

  const policy: BitBoxPolicy = {
    name,
    descriptorTemplate: result.descriptorTemplate,
    keyRoots: result.keyRoots
  };
  const { scriptConfig, accountKeypath } = scriptConfigForRegistration({
    policy,
    session
  });
  // BitBox can check whether a multisig/policy config is already approved, but
  // it cannot enumerate configs back to the app. The local policy list below is
  // still needed even when this returns true.
  const registered = await client.btcIsScriptConfigRegistered(
    apiNetwork(session),
    scriptConfig,
    accountKeypath
  );
  if (!registered) {
    try {
      await client.btcRegisterScriptConfig(
        apiNetwork(session),
        scriptConfig,
        accountKeypath,
        'autoXpubTpub',
        name
      );
    } catch (error) {
      // BitBox can report a duplicate if another registration check was stale.
      const duplicate =
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: unknown }).code === 'bitbox-duplicate';
      if (!duplicate) throw error;
      const registeredAfterDuplicate = await client.btcIsScriptConfigRegistered(
        apiNetwork(session),
        scriptConfig,
        accountKeypath
      );
      if (!registeredAfterDuplicate) throw error;
    }
  }
  store.policies.push(policy);
  return store;
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
  const originPath = originPathFromKeyRoot(policy.keyRoots[0] ?? '');
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
  change,
  index
}: AddressDisplayParams): Promise<string | void> {
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
  const standardPolicy = await standardPolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (standardPolicy)
    return displayStandardAddress({
      policy: standardPolicy,
      session,
      change: standardPolicy.change,
      index: standardPolicy.index
    });

  const policy = await knownPolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    ...(session.store.policies !== undefined
      ? { knownPolicies: session.store.policies }
      : {})
  });
  if (!policy)
    throw new Error(`BitBox policy not registered; call registerPolicy first`);
  return displayPolicyAddress({
    policy,
    session,
    change: policy.change,
    index: policy.index
  });
}

export async function signMessage({
  descriptor,
  session,
  message,
  change,
  index
}: MessageSigningParams): Promise<Uint8Array> {
  const { client } = session;
  if (typeof client.btcSignMessage !== 'function')
    throw new Error(`BitBox client does not support message signing`);

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
  const policy = await standardPolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
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
      keypath: addressKeypathFromPolicy({
        policy,
        session,
        change: policy.change,
        index: policy.index
      })
    },
    messageBytes(message)
  );
  return assertLegacyMessageSignature(result.electrumSig65, 'BitBox');
}
