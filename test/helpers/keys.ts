import * as ecc from '@bitcoinerlab/secp256k1';
import { mnemonicToSeedSync as mnemonicToSeedSyncBitcoinjs } from 'bip39';
import { BIP32Factory } from 'bip32';
import type { BIP32Interface } from 'bip32';
import { ECPairFactory } from 'ecpair';
import type { ECPairInterface } from 'ecpair';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync as mnemonicToSeedSyncScure } from '@scure/bip39';
import * as btc from '@scure/btc-signer';
import type { Network } from '../../dist';

const ECPair = ECPairFactory(ecc);
const BIP32 = BIP32Factory(ecc);

function isScureNode(node: BIP32Interface | HDKey): node is HDKey {
  return node instanceof HDKey;
}

function normalizePath(path: string): string {
  const p = path.replaceAll('H', "'").replaceAll('h', "'");
  if (p === 'm' || p === "m'") return 'm';
  if (p.startsWith('m/')) return p;
  if (p.startsWith('/')) return `m${p}`;
  return `m/${p}`;
}

export function createMasterNode(
  mnemonic: string,
  network: Network,
  isScure: boolean
): BIP32Interface | HDKey {
  const seed = isScure
    ? mnemonicToSeedSyncScure(mnemonic)
    : mnemonicToSeedSyncBitcoinjs(mnemonic);
  if (isScure) return HDKey.fromMasterSeed(seed, network.bip32);
  return BIP32.fromSeed(seed, network);
}

export function deriveNodePubKey(
  node: BIP32Interface | HDKey,
  path: string
): Uint8Array {
  if (isScureNode(node)) {
    const derived = node.derive(normalizePath(path));
    if (!derived.publicKey)
      throw new Error(
        'Error: scure HDKey missing publicKey at derivation path'
      );
    return derived.publicKey;
  }
  return node.derivePath(path).publicKey;
}

export function createPrivKeySigner(
  privateKey: Uint8Array,
  isScure: boolean
): ECPairInterface | Uint8Array {
  if (isScure) return privateKey;
  return ECPair.fromPrivateKey(privateKey);
}

export function createRandomSingleKeySigner(
  isScure: boolean
): ECPairInterface | Uint8Array {
  if (isScure) {
    return btc.utils.randomPrivateKeyBytes();
  }
  return ECPair.makeRandom();
}

export function getPubKey(signer: ECPairInterface | Uint8Array): Uint8Array {
  if (signer instanceof Uint8Array) {
    return secp256k1.getPublicKey(signer, true);
  }
  return signer.publicKey;
}

export function getXOnlyPubKey(
  signer: ECPairInterface | Uint8Array
): Uint8Array {
  return getPubKey(signer).slice(1, 33);
}
