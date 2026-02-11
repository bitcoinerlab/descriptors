// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { mnemonicToSeedSync } from 'bip39';
import { networks } from 'bitcoinjs-lib';
import type { Network } from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory, scriptExpressions } from '../dist/';

const { BIP32 } = DescriptorsFactory(ecc);

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

function cloneNetwork(network: Network): Network {
  return {
    ...network,
    bip32: {
      ...network.bip32
    }
  };
}

describe('scriptExpressions network detection', () => {
  test('wpkhBIP32 uses coin type 0 for mainnet network clone', () => {
    const mainnetClone = cloneNetwork(networks.bitcoin);
    const masterNode = BIP32.fromSeed(
      mnemonicToSeedSync(MNEMONIC),
      networks.bitcoin
    );

    const descriptor = scriptExpressions.wpkhBIP32({
      masterNode,
      network: mainnetClone,
      account: 0,
      change: 0,
      index: '*'
    });

    expect(descriptor).toContain(`/84'/0'/0'`);
  });

  test('wpkhBIP32 uses coin type 1 for testnet network clone', () => {
    const testnetClone = cloneNetwork(networks.testnet);
    const masterNode = BIP32.fromSeed(
      mnemonicToSeedSync(MNEMONIC),
      networks.testnet
    );

    const descriptor = scriptExpressions.wpkhBIP32({
      masterNode,
      network: testnetClone,
      account: 0,
      change: 0,
      index: '*'
    });

    expect(descriptor).toContain(`/84'/1'/0'`);
  });

  test('trBIP32 uses coin type 0 for mainnet network clone', () => {
    const mainnetClone = cloneNetwork(networks.bitcoin);
    const masterNode = BIP32.fromSeed(
      mnemonicToSeedSync(MNEMONIC),
      networks.bitcoin
    );

    const descriptor = scriptExpressions.trBIP32({
      masterNode,
      network: mainnetClone,
      account: 0,
      change: 0,
      index: 0
    });

    expect(descriptor).toContain(`/86'/0'/0'`);
  });
});
