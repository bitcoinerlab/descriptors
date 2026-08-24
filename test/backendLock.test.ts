// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import { createScureLib } from '../dist/scure';

test('rejects switching Bitcoin backends in one process', () => {
  createBitcoinjsLib(ecc);

  expect(() => createScureLib()).toThrow(
    'Cannot switch descriptors-core from the bitcoinjs backend to the scure backend in the same process. Use only one preset package: @bitcoinerlab/descriptors or @bitcoinerlab/descriptors-scure.'
  );
});
