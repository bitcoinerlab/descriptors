// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * @scure/btc-signer adapter for BitcoinLib.
 *
 * Wraps @scure/btc-signer and related scure/noble packages into the
 * BitcoinLib interface.
 */

import { schnorr } from '@noble/curves/secp256k1.js';
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
import { createScurePaymentsAdapter } from './scure/payments';
import { createScureScriptAdapter } from './scure/script';
import { createScureTransactionAdapter } from './scure/transaction';
import { createScureAddressAdapter } from './scure/address';
import { createScureECPairAdapter } from './scure/ecpair';
import { createScureBIP32Adapter } from './scure/bip32';
import { createScureCryptoAdapter } from './scure/crypto';
import { wrapScureTransaction } from './scure/psbt';
import { wrapScureHDKey, wrapScurePrivateKey } from './scureKeys';
export { wrapScureTransaction } from './scure/psbt';

/**
 * Create a BitcoinLib backed by @scure/btc-signer.
 */
export function createScureLib(): BitcoinLib {
  return setBitcoinLib({
    kind: 'scure',
    payments: createScurePaymentsAdapter(),
    script: createScureScriptAdapter(),
    Transaction: createScureTransactionAdapter(),
    crypto: createScureCryptoAdapter(),
    address: createScureAddressAdapter(),
    ECPair: createScureECPairAdapter(),
    BIP32: createScureBIP32Adapter(),
    toPsbt(psbt: PsbtLike | ScureTransactionLike) {
      return isScureTransaction(psbt)
        ? wrapScureTransaction(
            psbt as Parameters<typeof wrapScureTransaction>[0]
          )
        : psbt;
    },
    toECPairInterface(ecpair: ECPairInterfaceLike | Uint8Array) {
      return ecpair instanceof Uint8Array
        ? wrapScurePrivateKey(ecpair)
        : ecpair;
    },
    toBIP32Interface(node: BIP32InterfaceLike | ScureHDKeyLike) {
      return isScureHDKey(node) ? wrapScureHDKey(node) : node;
    },
    verifySchnorr(
      msghash: Uint8Array,
      pubkey: Uint8Array,
      signature: Uint8Array
    ) {
      return schnorr.verify(signature, msghash, pubkey);
    }
  });
}
