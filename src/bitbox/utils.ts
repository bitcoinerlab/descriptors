// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { fromHex } from 'uint8array-tools';

const HARDENED = 0x80000000;

export function bitboxKeypathFromString(path: string): number[] {
  const normalizedPath = path.startsWith('/') ? `m${path}` : path;
  const levels = normalizedPath.toLowerCase().replaceAll('h', "'").split('/');
  if (levels[0] !== 'm') throw new Error(`Invalid BitBox02 keypath ${path}`);

  return levels.slice(1).map(level => {
    const hardened = level.endsWith("'");
    const index = Number(hardened ? level.slice(0, -1) : level);
    if (!Number.isInteger(index) || index < 0 || index >= HARDENED)
      throw new Error(`Invalid BitBox02 keypath ${path}`);
    return hardened ? index + HARDENED : index;
  });
}

export function normalizeFingerprint(
  fingerprint: Uint8Array | string | number
): Uint8Array {
  if (fingerprint instanceof Uint8Array) {
    if (fingerprint.length !== 4)
      throw new Error(`BitBox02 master fingerprint must be 4 bytes`);
    return fingerprint;
  }

  if (typeof fingerprint === 'string') {
    const hex = fingerprint.startsWith('0x')
      ? fingerprint.slice(2)
      : fingerprint;
    if (!/^[0-9a-fA-F]{8}$/.test(hex))
      throw new Error(`Invalid BitBox02 master fingerprint ${fingerprint}`);
    return fromHex(hex);
  }

  if (
    !Number.isInteger(fingerprint) ||
    fingerprint < 0 ||
    fingerprint > 0xffffffff
  )
    throw new Error(`Invalid BitBox02 master fingerprint ${fingerprint}`);

  return Uint8Array.from([
    (fingerprint >>> 24) & 0xff,
    (fingerprint >>> 16) & 0xff,
    (fingerprint >>> 8) & 0xff,
    fingerprint & 0xff
  ]);
}
