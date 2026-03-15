import type { Network } from './bitcoinLib';

export function isBitcoinMainnet(
  network: Network,
  bitcoinNetwork: Network
): boolean {
  return (
    network.bech32 === bitcoinNetwork.bech32 &&
    network.bip32.public === bitcoinNetwork.bip32.public &&
    network.bip32.private === bitcoinNetwork.bip32.private &&
    network.pubKeyHash === bitcoinNetwork.pubKeyHash &&
    network.scriptHash === bitcoinNetwork.scriptHash &&
    network.wif === bitcoinNetwork.wif
  );
}

export function coinTypeFromNetwork(
  network: Network,
  bitcoinNetwork: Network
): 0 | 1 {
  return isBitcoinMainnet(network, bitcoinNetwork) ? 0 : 1;
}
