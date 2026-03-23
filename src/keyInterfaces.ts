// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  type ECPairInterfaceLike,
  type BIP32InterfaceLike,
  type ScureHDKeyLike
} from './bitcoinLib';

function isScureHDKey(
  node: BIP32InterfaceLike | ScureHDKeyLike
): node is ScureHDKeyLike {
  const candidate = node as ScureHDKeyLike;
  return (
    typeof candidate.fingerprint === 'number' &&
    typeof candidate.derive === 'function' &&
    typeof candidate.deriveChild === 'function' &&
    typeof candidate.publicExtendedKey === 'string' &&
    typeof candidate.privateExtendedKey === 'string'
  );
}

/** @internal */
export function toECPairInterface(
  ecpair: ECPairInterfaceLike | Uint8Array
): ECPairInterfaceLike {
  if (ecpair instanceof Uint8Array) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { wrapScurePrivateKey } = require('./adapters/scureKeys');
      return wrapScurePrivateKey(ecpair);
    } catch (error) {
      throw new Error(
        'Failed to load scure key adapter. ' +
          'Make sure @noble/curves is installed as a peer dependency. ' +
          'Original error: ' +
          (error instanceof Error ? error.message : String(error))
      );
    }
  }

  // Already a bitcoinjs-lib compatible ECPairInterface
  return ecpair;
}

/** @internal */
export function toBIP32Interface(
  node: BIP32InterfaceLike | ScureHDKeyLike
): BIP32InterfaceLike {
  if (isScureHDKey(node)) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { wrapScureHDKey } = require('./adapters/scureKeys');
      return wrapScureHDKey(node);
    } catch (error) {
      throw new Error(
        'Failed to load scure key adapter. ' +
          'Make sure @scure/bip32 is installed as a peer dependency. ' +
          'Original error: ' +
          (error instanceof Error ? error.message : String(error))
      );
    }
  }

  // Already a bitcoinjs-lib compatible Bip32Interface
  return node;
}
