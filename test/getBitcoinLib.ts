// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Provides the BitcoinLib adapter for tests based on BITCOIN_LIB env var.
// BITCOIN_LIB=scure  → @scure/btc-signer adapter
// BITCOIN_LIB=bitcoinjs (or unset) → bitcoinjs-lib adapter (default)

import * as ecc from '@bitcoinerlab/secp256k1';
import { type BitcoinLib } from '../dist';

export function getBitcoinLib(): BitcoinLib {
  if (process.env['BITCOIN_LIB'] === 'scure') {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require('../dist/scure') as {
      createScureLib: (e: typeof ecc) => BitcoinLib;
    };
    return mod.createScureLib(ecc);
  } else {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require('../dist/adapters/bitcoinjs') as {
      createBitcoinjsLib: (e: typeof ecc) => BitcoinLib;
    };
    return mod.createBitcoinjsLib(ecc);
  }
}
