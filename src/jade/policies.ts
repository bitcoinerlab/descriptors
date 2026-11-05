// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { HWWPolicy } from '../hww/policies';
import type { JadePolicy, JadeSession } from './types';

/** Rejects policy forms that current Jade firmware cannot sign. */
export function assertJadePolicySupported(policy: HWWPolicy): void {
  if (
    policy.descriptorTemplate.startsWith('tr(') &&
    policy.descriptorTemplate.includes(',')
  )
    throw new Error(
      `Jade supports only single-key Taproot. Taproot trees and script-path spending are not supported.`
    );
}

/** Converts the shared hardware-wallet policy into Jade's BIP388 fields. */
export function jadeDescriptorFromPolicy(policy: HWWPolicy): {
  descriptor: string;
  datavalues: Record<string, string>;
} {
  return {
    descriptor: policy.descriptorTemplate.replaceAll('/**', '/<0;1>/*'),
    datavalues: Object.fromEntries(
      policy.keyRoots.map((keyRoot, index) => [`@${index}`, keyRoot])
    )
  };
}

/** Checks that a named Jade record still contains the app's policy. */
export async function assertDevicePolicyMatches({
  policy,
  session
}: {
  policy: JadePolicy;
  session: JadeSession;
}): Promise<void> {
  if (!policy.name) throw new Error(`Jade policy has no registration name`);
  const expected = jadeDescriptorFromPolicy(policy);
  const devicePolicy = await session.client.getRegisteredDescriptor(
    policy.name
  );
  const keys = Object.keys(devicePolicy.datavalues);
  const sameDataValues =
    keys.length === Object.keys(expected.datavalues).length &&
    keys.every(
      key => devicePolicy.datavalues[key] === expected.datavalues[key]
    );
  if (devicePolicy.descriptor !== expected.descriptor || !sameDataValues)
    throw new Error(
      `Jade policy name "${policy.name}" is already used by another policy`
    );
}
