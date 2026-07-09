// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { fromHex, fromUtf8, toHex } from 'uint8array-tools';
import {
  getOutputConstructorOrThrow,
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
  index
}: {
  descriptor: string;
  network: Network;
  change?: number;
  index?: number;
}): OutputInstance {
  const Output = getOutputConstructorOrThrow();
  return new Output({
    descriptor,
    ...(descriptor.includes('*') && index !== undefined ? { index } : {}),
    ...(change !== undefined ? { change } : {}),
    network
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
