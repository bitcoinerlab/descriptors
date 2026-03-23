// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * Separate entry point for the @scure/btc-signer adapter.
 *
 * Usage:
 *   import { createScureLib } from '@bitcoinerlab/descriptors/scure';
 *   import { DescriptorsFactory } from '@bitcoinerlab/descriptors';
 *
 *   const lib = createScureLib();
 *   const { Output } = DescriptorsFactory(lib);
 *   const psbt = lib.Psbt.fromTransaction(nativeTransaction);
 *   const scureTx = psbt.raw;
 */
export { createScureLib } from './adapters/scure';
