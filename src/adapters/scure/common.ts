// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { type Network, networks } from '../../networks';
import { readUInt32, writeUInt32 } from 'uint8array-tools';

/** Convert our Network to the format expected by @scure/btc-signer */
export function toBtcSignerNetwork(network: Network) {
  return {
    bech32: network.bech32,
    pubKeyHash: network.pubKeyHash,
    scriptHash: network.scriptHash,
    wif: network.wif
  };
}

export function scureVersions(network?: Network): {
  public: number;
  private: number;
} {
  const net = network ?? networks.bitcoin;
  return {
    public: net.bip32.public,
    private: net.bip32.private
  };
}

export function uint32ToBytesBE(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  writeUInt32(bytes, 0, value, 'BE');
  return bytes;
}

export function uint32FromBytesBE(bytes: Uint8Array): number {
  if (bytes.length !== 4) throw new Error('Expected 4-byte fingerprint');
  return readUInt32(bytes, 0, 'BE');
}
