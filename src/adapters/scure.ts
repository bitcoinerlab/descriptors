// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * @scure/btc-signer adapter for BitcoinLib.
 *
 * Wraps @scure/btc-signer and related scure/noble packages into the
 * BitcoinLib interface.
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import type { BitcoinLib } from '../bitcoinLib';
import { createScurePaymentsAdapter } from './scure/payments';
import { createScureScriptAdapter } from './scure/script';
import { createScureTransactionAdapter } from './scure/transaction';
import { createScureAddressAdapter } from './scure/address';
import { createScureECPairAdapter } from './scure/ecpair';
import { createScureBIP32Adapter } from './scure/bip32';
export { wrapScureTransaction } from './scure/psbt';

/**
 * Create a BitcoinLib backed by @scure/btc-signer.
 */
export function createScureLib(): BitcoinLib {
  return {
    payments: createScurePaymentsAdapter(),
    script: createScureScriptAdapter(),
    Transaction: createScureTransactionAdapter(),
    address: createScureAddressAdapter(),
    ECPair: createScureECPairAdapter(),
    BIP32: createScureBIP32Adapter(),
    verifySchnorr(
      msghash: Uint8Array,
      pubkey: Uint8Array,
      signature: Uint8Array
    ) {
      return schnorr.verify(signature, msghash, pubkey);
    }
  };
}
