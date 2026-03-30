// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * bitcoinjs-lib adapter for BitcoinLib.
 *
 * Wraps bitcoinjs-lib, ecpair, bip32 and related packages into the
 * BitcoinLib interface.  This is the default backend and should produce
 * identical behaviour to the pre-refactor library.
 */

import {
  address,
  crypto,
  payments,
  Transaction,
  initEccLib,
  script
} from 'bitcoinjs-lib';
import { type BIP32API, BIP32Factory } from 'bip32';
import { type ECPairAPI, ECPairFactory } from 'ecpair';
import type { TinySecp256k1Interface } from '../types';
import {
  isScureHDKey,
  isScureTransaction,
  setBitcoinLib,
  type BitcoinLib,
  type ECPairInterfaceLike,
  type BIP32InterfaceLike,
  type PsbtLike,
  type ScureHDKeyLike,
  type ScureTransactionLike
} from '../bitcoinLib';

/**
 * Create a BitcoinLib backed by bitcoinjs-lib.
 *
 * @param ecc  A TinySecp256k1Interface (e.g. `@bitcoinerlab/secp256k1`).
 */
export function createBitcoinjsLib(ecc: TinySecp256k1Interface): BitcoinLib {
  initEccLib(ecc);

  const ECPair: ECPairAPI = ECPairFactory(ecc);
  const BIP32: BIP32API = BIP32Factory(ecc);

  if (!ecc.verifySchnorr)
    throw new Error(
      'TinySecp256k1Interface is not initialized properly: verifySchnorr is missing.'
    );

  return setBitcoinLib({
    kind: 'bitcoinjs',
    payments,
    script,
    Transaction,
    crypto,
    address,
    ECPair,
    BIP32,
    toPsbt(psbt: PsbtLike | ScureTransactionLike) {
      if (isScureTransaction(psbt)) {
        throw new Error(
          'Scure transaction support is not available for the active backend. ' +
            'Initialize descriptors-core with createScureLib() or use @bitcoinerlab/descriptors-scure ' +
            'before passing @scure/btc-signer transactions.'
        );
      }
      return psbt;
    },
    toECPairInterface(ecpair: ECPairInterfaceLike | Uint8Array) {
      if (ecpair instanceof Uint8Array) {
        throw new Error(
          'Scure private-key support is not available for the active backend. ' +
            'Initialize descriptors-core with createScureLib() or use @bitcoinerlab/descriptors-scure ' +
            'before passing raw Uint8Array private keys.'
        );
      }
      return ecpair;
    },
    toBIP32Interface(node: BIP32InterfaceLike | ScureHDKeyLike) {
      if (isScureHDKey(node)) {
        throw new Error(
          'Scure HDKey support is not available for the active backend. ' +
            'Initialize descriptors-core with createScureLib() or use @bitcoinerlab/descriptors-scure ' +
            'before passing @scure/bip32 HDKey values.'
        );
      }
      return node;
    },
    verifySchnorr: ecc.verifySchnorr
  });
}
