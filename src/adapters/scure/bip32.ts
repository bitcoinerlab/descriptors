// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { HDKey } from '@scure/bip32';
import type { BitcoinLib } from '../../bitcoinLib';
import type { Network } from '../../networks';
import { wrapScureHDKey } from '../scureKeys';
import { scureVersions } from './common';

export function createScureBIP32Adapter(): BitcoinLib['BIP32'] {
  return {
    fromBase58(inString: string, network?: Network) {
      const hd = HDKey.fromExtendedKey(inString, scureVersions(network));
      return wrapScureHDKey(hd);
    }
  };
}
