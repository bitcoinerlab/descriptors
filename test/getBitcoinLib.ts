// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Provides the BitcoinLib adapter for tests based on BITCOIN_LIB env var.
// BITCOIN_LIB=scure  → @scure/btc-signer adapter
// BITCOIN_LIB=bitcoinjs (or unset) → bitcoinjs-lib adapter (default)

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks, type BitcoinLib, type Network } from '../dist';

let _lib: BitcoinLib | undefined;

export function getLib(): BitcoinLib {
  if (_lib) return _lib;
  if (process.env['BITCOIN_LIB'] === 'scure') {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require('../dist/scure') as {
      createScureLib: (e: typeof ecc) => BitcoinLib;
    };
    _lib = mod.createScureLib(ecc);
  } else {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require('../dist/adapters/bitcoinjs') as {
      createBitcoinjsLib: (e: typeof ecc) => BitcoinLib;
    };
    _lib = mod.createBitcoinjsLib(ecc);
  }
  return _lib;
}

// Convenience re-exports so test files can do:
//   import { lib, networks } from './getLib';
// instead of:
//   import { networks } from 'bitcoinjs-lib';
export const lib: BitcoinLib = getLib();
export const testNetworks: {
  bitcoin: Network;
  testnet: Network;
  regtest: Network;
} = networks;
export { testNetworks as networks };
export type { Network };
