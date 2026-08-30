// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { fromHex, fromUtf8, toHex } from 'uint8array-tools';
// OutputConstructor is needed only for the deprecated LedgerManager override.
// Remove this type import and the optional Output parameters in v4.
import {
  getOutputConstructorOrThrow,
  type OutputConstructor,
  type OutputInstance
} from '../descriptors';
import { assertChangeIndexKeyPath } from '../keyExpressions';
import type { Network } from '../networks';

/**
 * Checks that address position params match the descriptor shape.
 *
 * Use `index` for ranged descriptors (`*`). Use `change` only when the
 * descriptor has a multipath branch such as `/**` or `/<0;1>/*`.
 */
export function assertDescriptorParams({
  descriptor,
  change,
  index
}: {
  descriptor: string;
  change?: number;
  index?: number;
}): void {
  const isRanged = descriptor.includes('*');
  const hasMultipath = /\/(?:\*\*|<[^<>]+>)/.test(descriptor);

  if (isRanged && index === undefined)
    throw new Error(`Error: index was not provided for ranged descriptor`);
  if (!isRanged && index !== undefined)
    throw new Error(`Error: index passed for non-ranged descriptor`);
  if (hasMultipath && change === undefined)
    throw new Error(`Error: change was not provided for multipath descriptor`);
  if (!hasMultipath && change !== undefined)
    throw new Error(`Error: change passed for descriptor without multipath`);
}

/** Builds an Output from a descriptor and optional address position. */
export function outputFromDescriptor({
  descriptor,
  network,
  change,
  index,
  legacyOutput
}: {
  descriptor: string;
  network: Network;
  change?: number;
  index?: number;
  /**
   * @deprecated 3.x LedgerManager compatibility only. Remove in v4 and always
   * use the active package backend.
   */
  legacyOutput?: OutputConstructor;
}): OutputInstance {
  // In v4, remove legacyOutput and keep getOutputConstructorOrThrow().
  const Output = legacyOutput ?? getOutputConstructorOrThrow();
  return new Output({
    descriptor,
    ...(descriptor.includes('*') && index !== undefined ? { index } : {}),
    ...(change !== undefined ? { change } : {}),
    network
  });
}

/**
 * Builds one sample `Output` so policy derivation can reuse the existing
 * descriptor expansion and validation code.
 *
 * An `Output` needs one concrete key position, while a hardware-wallet policy
 * covers a range. This function uses index `0` as a deterministic sample. When
 * the descriptor contains the receive/change range `/**` or `/<0;1>/*`, it also
 * selects branch `0`; a fixed branch such as `/1/*` stays unchanged. Policy
 * derivation later replaces the concrete position with `/**`, so the resulting
 * policy still covers receive and change outputs at every index. The sample
 * `Output` is used only in memory and is never sent to the device.
 */
export function sampleOutputFromPolicyDescriptor({
  descriptor,
  network,
  legacyOutput
}: {
  descriptor: string;
  network: Network;
  /**
   * @deprecated 3.x LedgerManager compatibility only. Remove in v4 and always
   * use the active package backend.
   */
  legacyOutput?: OutputConstructor;
}): OutputInstance {
  const multipathTokens = descriptor.match(/\/(?:\*\*|<[^<>]+>)/g) ?? [];
  if (multipathTokens.some(token => token !== '/**' && token !== '/<0;1>'))
    throw new Error(
      `Error: hardware wallet policies support only receive/change multipath /** or /<0;1>/*`
    );

  // Resolve only what Output needs. These values identify the sample output;
  // they do not limit the policy produced from it.
  return outputFromDescriptor({
    descriptor,
    network,
    ...(multipathTokens.length > 0 ? { change: 0 } : {}),
    index: 0,
    ...(legacyOutput !== undefined ? { legacyOutput } : {})
  });
}

/** Builds a descriptor key expression from hardware-wallet device callbacks. */
export async function keyExpressionHWW({
  getMasterFingerprint,
  getAccountXpub,
  originPath,
  keyPath,
  change,
  index
}: {
  /** Reads the connected device master fingerprint. */
  getMasterFingerprint(): Promise<Uint8Array>;
  /** Reads the account xpub for the descriptor origin path. */
  getAccountXpub(originPath: string): Promise<string>;
  originPath: string;
  change?: number;
  index?: number | '*';
  keyPath?: string;
}): Promise<string> {
  assertChangeIndexKeyPath({
    ...(change !== undefined ? { change } : {}),
    ...(index !== undefined ? { index } : {}),
    ...(keyPath !== undefined ? { keyPath } : {})
  });

  const masterFingerprint = await getMasterFingerprint();
  const origin = `[${toHex(masterFingerprint)}${originPath}]`;
  const xpub = await getAccountXpub(originPath);

  const keyRoot = `${origin}${xpub}`;
  if (keyPath !== undefined) return `${keyRoot}${keyPath}`;
  else return `${keyRoot}/${change}/${index}`;
}

/** Splits a descriptor key root into origin data and xpub. */
export function parseKeyRoot(keyRoot: string): {
  masterFingerprint?: Uint8Array;
  originPath?: string;
  xpub: string;
} {
  const originMatch = keyRoot.match(/^\[([0-9a-fA-F]{8})([^\]]*)\](.+)$/);
  if (!originMatch) return { xpub: keyRoot };
  return {
    masterFingerprint: fromHex(originMatch[1]!),
    ...(originMatch[2] ? { originPath: originMatch[2] } : {}),
    xpub: originMatch[3]!
  };
}

/** Returns only the origin path from a descriptor key root. */
export function originPathFromKeyRoot(keyRoot: string): string | undefined {
  return parseKeyRoot(keyRoot).originPath;
}

/** Converts a text message to bytes and leaves byte messages unchanged. */
export function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === 'string' ? fromUtf8(message) : message;
}

/** Checks that a device returned a 65-byte legacy message signature. */
export function assertLegacyMessageSignature(
  signature: Uint8Array,
  device: string
): Uint8Array {
  if (signature.length !== 65)
    throw new Error(`${device} client returned an invalid message signature`);
  return signature;
}
