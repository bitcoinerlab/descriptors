// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * Separate entry point for the bitcoinjs-lib adapter.
 *
 * Usage:
 *   import { createBitcoinjsLib } from '@bitcoinerlab/descriptors/bitcoinjs';
 *   import { DescriptorsFactory } from '@bitcoinerlab/descriptors';
 *   import * as ecc from '@bitcoinerlab/secp256k1';
 *
 *   const lib = createBitcoinjsLib(ecc);
 *   const { Output } = DescriptorsFactory(lib);
 */
export { createBitcoinjsLib } from './adapters/bitcoinjs';
