// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  type ECPairInterfaceLike,
  type BIP32InterfaceLike,
  type ScureHDKeyLike,
  isScureHDKey
} from './bitcoinLib';

export function toECPairInterface(
  ecpair: ECPairInterfaceLike | Uint8Array
): ECPairInterfaceLike {
  if (ecpair instanceof Uint8Array) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { wrapScurePrivateKey } = require('./adapters/scureKeys') as {
        wrapScurePrivateKey: (privateKey: Uint8Array) => ECPairInterfaceLike;
      };
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

export function toBIP32Interface(
  node: BIP32InterfaceLike | ScureHDKeyLike
): BIP32InterfaceLike {
  if (isScureHDKey(node)) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { wrapScureHDKey } = require('./adapters/scureKeys') as {
        wrapScureHDKey: (node: ScureHDKeyLike) => BIP32InterfaceLike;
      };
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
