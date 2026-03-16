// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * Separate entry point for the @scure/btc-signer adapter.
 *
 * Usage:
 *   import { createScureLib } from '@bitcoinerlab/descriptors/scure';
 *   import { DescriptorsFactory } from '@bitcoinerlab/descriptors';
 *   import * as ecc from '@bitcoinerlab/secp256k1';
 *
 *   const lib = createScureLib(ecc);
 *   const { Output } = DescriptorsFactory(lib);
 */
export { createScureLib } from './adapters/scure';
