// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { base58 } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { compare } from 'uint8array-tools';
import type { BitcoinLib } from '../../bitcoinLib';
import type { Network } from '../../networks';
import { sha256 } from '@noble/hashes/sha2.js';
import { wrapScurePrivateKey, wrapScurePublicKey } from '../scureKeys';

function decodeWIF(
  wifString: string,
  network?: Network | Network[]
): { privateKey: Uint8Array; compressed: boolean } {
  const raw = base58.decode(wifString);
  if (!(raw.length === 37 || raw.length === 38)) {
    throw new Error('Wrong WIF length');
  }

  const payload = raw.slice(0, raw.length - 4);
  const checksum = raw.slice(raw.length - 4);
  const expected = sha256(sha256(payload)).slice(0, 4);
  if (compare(checksum, expected) !== 0) {
    throw new Error('Invalid WIF checksum');
  }

  const version = payload[0];
  if (version === undefined) throw new Error('Invalid WIF payload');

  if (Array.isArray(network)) {
    if (!network.some(net => net.wif === version)) {
      throw new Error('Invalid network version');
    }
  } else if (network && network.wif !== version) {
    throw new Error('Invalid network version');
  }

  if (!(payload.length === 33 || payload.length === 34)) {
    throw new Error('Wrong WIF length');
  }
  if (payload.length === 34 && payload[33] !== 0x01) {
    throw new Error('Invalid WIF compression flag');
  }

  return {
    privateKey: payload.slice(1, 33),
    compressed: payload.length === 34
  };
}

export function createScureECPairAdapter(): BitcoinLib['ECPair'] {
  return {
    isPoint(maybePoint: unknown): boolean {
      return (
        maybePoint instanceof Uint8Array &&
        secp256k1.utils.isValidPublicKey(maybePoint)
      );
    },
    fromPublicKey(
      buffer: Uint8Array,
      _options?: { compressed?: boolean; network?: Network }
    ) {
      return wrapScurePublicKey(buffer);
    },
    fromWIF(wifString: string, network?: Network | Network[]) {
      const { privateKey, compressed } = decodeWIF(wifString, network);
      return wrapScurePrivateKey(privateKey, compressed);
    }
  };
}
