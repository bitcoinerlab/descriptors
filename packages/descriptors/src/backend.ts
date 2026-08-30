import * as core from '@bitcoinerlab/descriptors-core';
import { createBitcoinjsLib } from '@bitcoinerlab/descriptors-core/bitcoinjs';
import * as ecc from '@bitcoinerlab/secp256k1';

/** Backend-bound descriptor primitives shared by this preset package. */
export const bound = core.DescriptorsFactory(createBitcoinjsLib(ecc));
