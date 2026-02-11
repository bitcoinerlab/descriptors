import { networks } from 'bitcoinjs-lib';
import type { Network } from 'bitcoinjs-lib';

export function isBitcoinMainnet(network: Network): boolean {
  return (
    network.bech32 === networks.bitcoin.bech32 &&
    network.bip32.public === networks.bitcoin.bip32.public &&
    network.bip32.private === networks.bitcoin.bip32.private &&
    network.pubKeyHash === networks.bitcoin.pubKeyHash &&
    network.scriptHash === networks.bitcoin.scriptHash &&
    network.wif === networks.bitcoin.wif
  );
}

export function coinTypeFromNetwork(network: Network): 0 | 1 {
  return isBitcoinMainnet(network) ? 0 : 1;
}
