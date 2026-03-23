// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
import type { BitcoinLib } from '../../bitcoinLib';
import { type Network, networks } from '../../networks';
import { toBtcSignerNetwork } from './common';

export function createScureAddressAdapter(): BitcoinLib['address'] {
  return {
    toOutputScript(addr: string, network?: Network): Uint8Array {
      const net = toBtcSignerNetwork(network ?? networks.bitcoin);
      const decoded = btc.Address(net).decode(addr);
      return btc.OutScript.encode(decoded);
    }
  };
}
