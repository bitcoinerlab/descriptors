// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// BIP86: Taproot BIP32 Derivation Path and Extended Key Version
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
// Read Interesting discussion here: https://github.com/bitcoinjs/bitcoinjs-lib/issues/1871

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks } from 'bitcoinjs-lib';
import { DescriptorsFactory, scriptExpressions } from '../dist/';
import { mnemonicToSeedSync } from 'bip39';
const { trBIP32 } = scriptExpressions;
const { Output, BIP32 } = DescriptorsFactory(ecc);
const network = networks.bitcoin;
const masterNode = BIP32.fromSeed(
  mnemonicToSeedSync(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  ),
  network
);

describe('BIP86 Taproot Derivation Path Tests', () => {
  // Test vector from BIP86 specification
  // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors

  test("First receiving address m/86'/0'/0'/0/0", () => {
    // Account 0, first receiving address = m/86'/0'/0'/0/0
    // Expected values from BIP86 specification:
    // xprv = xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T
    // xpub = xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B
    // internal_key = cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
    // output_key = a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
    // scriptPubKey = 5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
    // address = bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr

    const descriptor = trBIP32({
      masterNode,
      network,
      account: 0,
      change: 0,
      index: 0
    });

    const output = new Output({ descriptor, network });
    const address = output.getAddress();
    const scriptPubKey = output.getScriptPubKey().toString('hex');
    const internalKey = output.getPayment().internalPubkey?.toString('hex');
    const pubKey = output.getPayment().pubkey?.toString('hex');

    // Verify the generated address matches the expected value from BIP86 spec
    expect(address).toBe(
      'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'
    );

    // Verify the scriptPubKey matches the expected value (with 5120 prefix for OP_PUSHBYTES_32 + 32-byte key)
    expect(scriptPubKey).toBe(
      '5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c'
    );

    expect(internalKey).toBe(
      'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115'
    );

    expect(pubKey).toBe(
      'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c'
    );
  });

  test('Basic Taproot descriptor functionality', () => {
    const descriptor = trBIP32({
      masterNode,
      network,
      account: 0,
      change: 0,
      index: 0
    });

    const output = new Output({ descriptor, network });

    // Verify we can get an address
    expect(output.getAddress()).toBeTruthy();

    // Verify it's a Taproot address (starts with bc1p for mainnet)
    expect(output.getAddress().startsWith('bc1p')).toBe(true);

    // Verify it's recognized as Taproot
    expect(output.isTaproot()).toBe(true);
  });
});
