import * as ecc from '@bitcoinerlab/secp256k1';
import { BIP32Factory } from 'bip32';
import { ECPairFactory } from 'ecpair';

export function createKeyFactories() {
  const ECPair = ECPairFactory(ecc);
  const BIP32 = BIP32Factory(ecc);
  return { BIP32, ECPair };
}
