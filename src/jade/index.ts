/**
 * Blockstream Jade helpers shared by both preset packages.
 *
 * This entrypoint keeps Jade transports optional. Pass a compatible USB, BLE
 * or development TCP driver module to `connect(...)`.
 *
 * @module jade
 */

// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  assertDescriptorParams,
  assertLegacyMessageSignature,
  messageBytes,
  originPathFromKeyRoot,
  outputFromDescriptor,
  sampleOutputFromPolicyDescriptor
} from '../hww/helpers';
import {
  derivePolicyFromOutput,
  findKnownPolicy,
  isStandardPolicy,
  samePolicy
} from '../hww/policies';
import { compare, fromBase64, fromUtf8, toUtf8 } from 'uint8array-tools';
import {
  getMasterFingerprint,
  jadeNetwork,
  jadePath,
  singlesigVariant
} from './client';
import {
  assertDevicePolicyMatches,
  assertJadePolicySupported,
  jadeDescriptorFromPolicy
} from './policies';
import type { JadePolicy, JadeSession, JadeStore } from './types';

export { getMasterFingerprint, getVersion, getXpub } from './client';
export { connect } from './connectors';
export { keyExpression } from './keyExpressions';
export * as scriptExpressions from './scriptExpressions';
export * as signers from './signers';
export type {
  JadeClient,
  JadeConnectionMode,
  JadeDriverModule,
  JadeHttpRequest,
  JadeHttpRequestFunction
} from './types';

export type Session = JadeSession;
export type Store = JadeStore;

type AddressDisplayParams = {
  descriptor: string;
  session: JadeSession;
  change?: number;
  index?: number;
};

/** Registers a non-standard BIP388 descriptor policy with Jade when needed. */
export async function registerPolicy({
  descriptor,
  session,
  name
}: {
  descriptor: string;
  session: JadeSession;
  /** Printable ASCII name, from 1 to 15 characters. */
  name: string;
}): Promise<boolean | undefined> {
  const sampleOutput = sampleOutputFromPolicyDescriptor({
    descriptor,
    network: session.network
  });
  const derivedPolicy = await derivePolicyFromOutput({
    output: sampleOutput,
    getMasterFingerprint: () => getMasterFingerprint({ session })
  });
  if (!derivedPolicy)
    throw new Error(`Error: output does not have a Jade input`);
  assertJadePolicySupported(derivedPolicy);
  if (
    isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network: session.network
    })
  )
    return undefined;

  if (!/^[\x21-\x7e]{1,15}$/.test(name))
    throw new Error(
      `Jade policy name must contain 1 to 15 printable ASCII characters without spaces`
    );

  if (!session.store.policies) session.store.policies = [];
  const namedPolicy = session.store.policies.find(
    policy => policy.name === name
  );
  if (namedPolicy && !samePolicy(namedPolicy, derivedPolicy))
    throw new Error(
      `Jade policy name "${name}" is already used by another policy`
    );

  const existingPolicy = findKnownPolicy({
    derivedPolicy,
    knownPolicies: session.store.policies
  }) as JadePolicy | null;
  if (existingPolicy && existingPolicy.name !== name)
    throw new Error(
      `Error: policy was already registered with a different name: ${existingPolicy.name}`
    );

  const expected = jadeDescriptorFromPolicy(derivedPolicy);
  const registered = await session.client.getRegisteredDescriptors();
  const wasRegistered = Object.prototype.hasOwnProperty.call(registered, name);
  if (wasRegistered) {
    await assertDevicePolicyMatches({
      policy: { ...derivedPolicy, name },
      session
    });
  } else {
    const result = await session.client.registerDescriptor(
      jadeNetwork(session.network),
      name,
      expected.descriptor,
      expected.datavalues
    );
    if (!result) throw new Error(`Jade did not register the policy`);
  }

  if (!existingPolicy)
    session.store.policies.push({
      name,
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots
    });
  return wasRegistered;
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
    throw new Error(`Error: output does not have a Jade input`);
  assertJadePolicySupported(derivedPolicy);

  if (
    isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network: session.network
    })
  ) {
    const originPath = originPathFromKeyRoot(derivedPolicy.keyRoots[0] ?? '');
    if (!originPath) throw new Error(`Jade key root missing origin path`);
    return session.client.getReceiveAddress(jadeNetwork(session.network), {
      variant: singlesigVariant(derivedPolicy.descriptorTemplate),
      path: jadePath(
        `m${originPath}/${derivedPolicy.change}/${derivedPolicy.index}`
      )
    });
  }

  const policy = findKnownPolicy({
    derivedPolicy,
    ...(session.store.policies !== undefined
      ? { knownPolicies: session.store.policies }
      : {})
  });
  if (!policy?.name)
    throw new Error(`Jade policy not registered; call registerPolicy first`);
  await assertDevicePolicyMatches({ policy, session });
  return session.client.getReceiveAddress(jadeNetwork(session.network), {
    descriptorName: policy.name,
    branch: policy.change,
    pointer: policy.index
  });
}

export async function signMessage({
  descriptor,
  session,
  message,
  change,
  index
}: AddressDisplayParams & {
  message: string | Uint8Array;
}): Promise<Uint8Array> {
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
    throw new Error(`Error: output does not have a Jade input`);
  if (
    !isStandardPolicy({
      descriptorTemplate: derivedPolicy.descriptorTemplate,
      keyRoots: derivedPolicy.keyRoots,
      network: session.network
    }) ||
    derivedPolicy.descriptorTemplate === 'tr(@0/**)'
  )
    throw new Error(
      `Jade message signing supports only standard single-key pkh, sh(wpkh), and wpkh descriptors`
    );

  const originPath = originPathFromKeyRoot(derivedPolicy.keyRoots[0] ?? '');
  if (!originPath) throw new Error(`Jade key root missing origin path`);
  const messageData = messageBytes(message);
  const messageText = toUtf8(messageData);
  if (compare(fromUtf8(messageText), messageData) !== 0)
    throw new Error(`Jade message bytes must contain valid UTF-8`);
  const result = await session.client.signMessage(
    jadePath(`m${originPath}/${derivedPolicy.change}/${derivedPolicy.index}`),
    messageText
  );
  const signature = typeof result === 'string' ? fromBase64(result) : result;
  return assertLegacyMessageSignature(signature, 'Jade');
}
