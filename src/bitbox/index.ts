/**
 * BitBox helpers shared by both preset packages.
 *
 * This entrypoint does not import a BitBox provider directly. Pass the selected
 * provider as a literal import to `connect(...)`.
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
  findKnownPolicy,
  isStandardPolicy
} from '../hww/policies';
import {
  assertDescriptorParams,
  assertLegacyMessageSignature,
  messageBytes,
  originPathFromKeyRoot,
  outputFromDescriptor,
  sampleOutputFromPolicyDescriptor
} from '../hww/helpers';
import { apiNetwork, getMasterFingerprint, simpleType } from './client';
import type { BitBoxPolicy, BitBoxSession, BitBoxStore } from './types';

export { getMasterFingerprint, getVersion, getXpub } from './client';
export { keyExpression } from './keyExpressions';
export * as scriptExpressions from './scriptExpressions';
export * as signers from './signers';
export { connect } from './connectors';

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
 *
 * A descriptor might point to one output, but the stored BitBox policy is
 * generalized to cover receive and change outputs at every index.
 *
 * For a ranged descriptor, registration expands one deterministic sample using
 * index `0`. It also uses branch `0` when the branch is the receive/change range
 * `/**`. A fixed branch stays unchanged. The sample is used to parse and
 * validate the descriptor; it is not the policy sent to the device.
 *
 * Returns whether BitBox reported the policy as already stored before this call
 * attempted registration. Standard policies return `undefined` because they do
 * not require registration.
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
}): Promise<boolean | undefined> {
  const { client, store, network } = session;
  // Parse the policy through one deterministic output. The policy derived
  // below is generalized back to /** and is not limited to that sample.
  const sampleOutput = sampleOutputFromPolicyDescriptor({
    descriptor,
    network
  });
  const readMasterFingerprint = () => getMasterFingerprint({ session });

  const derivedPolicy = await derivePolicyFromOutput({
    output: sampleOutput,
    getMasterFingerprint: readMasterFingerprint
  });
  if (!derivedPolicy)
    throw new Error(`Error: output does not have a BitBox02 input`);
  if (
    isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network
    })
  ) {
    simpleType(derivedPolicy.descriptorTemplate);
    return undefined;
  }

  if (!store.policies) store.policies = [];

  const existingPolicy = findKnownPolicy({
    derivedPolicy,
    knownPolicies: store.policies
  });
  let policy: BitBoxPolicy;
  if (existingPolicy) {
    if (existingPolicy.name !== name)
      throw new Error(
        `Error: policy was already registered with a different name: ${existingPolicy.name}`
      );
    policy = existingPolicy;
  } else {
    policy = {
      name,
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots
    };
  }
  assertPolicyCanDerive(policy);

  const { scriptConfig, accountKeypath } = scriptConfigForRegistration({
    policy,
    session
  });
  // BitBox can check whether a multisig/policy config is already approved, but
  // it cannot enumerate configs back to the app. The local policy list below is
  // still needed even when this returns true.
  const wasPolicyStoredOnDevice = await client.btcIsScriptConfigRegistered(
    apiNetwork(session),
    scriptConfig,
    accountKeypath
  );
  if (!wasPolicyStoredOnDevice) {
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
  if (!existingPolicy) store.policies.push(policy);
  return wasPolicyStoredOnDevice;
}

export async function displayAddress({
  descriptor,
  session,
  change,
  index
}: AddressDisplayParams): Promise<string> {
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
  const derivedPolicy = await derivePolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (!derivedPolicy)
    throw new Error(`Error: output does not have a BitBox02 input`);
  if (
    isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network: session.network
    })
  ) {
    const originPath = originPathFromKeyRoot(derivedPolicy.keyRoots[0] ?? '');
    if (!originPath) throw new Error(`BitBox02 key root missing origin path`);
    return session.client.btcAddress(
      apiNetwork(session),
      `m${originPath}/${derivedPolicy.change}/${derivedPolicy.index}`,
      { simpleType: simpleType(derivedPolicy.descriptorTemplate) },
      true
    );
  }

  const policy = findKnownPolicy({
    derivedPolicy,
    ...(session.store.policies !== undefined
      ? { knownPolicies: session.store.policies }
      : {})
  });
  if (!policy)
    throw new Error(`BitBox policy not registered; call registerPolicy first`);
  assertPolicyCanDerive(policy);
  return session.client.btcAddress(
    apiNetwork(session),
    addressKeypathFromPolicy({
      policy,
      session,
      change: policy.change,
      index: policy.index
    }),
    scriptConfigFromPolicy({ policy, session }),
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
  const derivedPolicy = await derivePolicyFromOutput({
    output,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (!derivedPolicy)
    throw new Error(`Error: output does not have a BitBox02 input`);
  if (
    !isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network: session.network
    })
  )
    throw new Error(
      `BitBox message signing supports only standard single-key sh(wpkh) and wpkh descriptors`
    );
  if (derivedPolicy.descriptorTemplate === 'pkh(@0/**)') {
    throw new Error(
      `BitBox02 does not support top-level legacy p2pkh descriptors; use shWpkh, wpkh, or tr`
    );
  }
  if (derivedPolicy.descriptorTemplate === 'tr(@0/**)')
    throw new Error(`BitBox02 does not support Taproot message signing`);

  const result = await client.btcSignMessage(
    apiNetwork(session),
    {
      scriptConfig: scriptConfigFromPolicy({ policy: derivedPolicy, session }),
      keypath: addressKeypathFromPolicy({
        policy: derivedPolicy,
        session,
        change: derivedPolicy.change,
        index: derivedPolicy.index
      })
    },
    messageBytes(message)
  );
  return assertLegacyMessageSignature(result.electrumSig65, 'BitBox');
}
