// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';

function loadAdapters() {
  jest.resetModules();
  return {
    createBitcoinjsLib:
      jest.requireActual<typeof import('../dist/bitcoinjs')>(
        '../dist/bitcoinjs'
      ).createBitcoinjsLib,
    createScureLib:
      jest.requireActual<typeof import('../dist/scure')>('../dist/scure')
        .createScureLib
  };
}

test('rejects switching from bitcoinjs to scure', () => {
  const { createBitcoinjsLib, createScureLib } = loadAdapters();
  createBitcoinjsLib(ecc);

  expect(() => createScureLib()).toThrow(
    'Cannot use the scure backend because this copy of descriptors-core already uses bitcoinjs.'
  );
  expect(() => createBitcoinjsLib(ecc)).not.toThrow();
});

test('rejects switching from scure to bitcoinjs', () => {
  const { createBitcoinjsLib, createScureLib } = loadAdapters();
  createScureLib();

  expect(() => createBitcoinjsLib(ecc)).toThrow(
    'Cannot use the bitcoinjs backend because this copy of descriptors-core already uses scure.'
  );
  expect(() => createScureLib()).not.toThrow();
});
