//https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#user-content-Address_derivation

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
describe('BIP86', () => {
  test('BIP86', () => {
    const descriptor = trBIP32({
      masterNode,
      network,
      account: 0,
      change: 0,
      index: 0
    });
    const output = new Output({ descriptor, network });
    console.log(output.getAddress());
  });
});
