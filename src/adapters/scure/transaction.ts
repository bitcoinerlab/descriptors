// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { hex } from '@scure/base';
import { RawTx, RawOldTx } from '@scure/btc-signer/script.js';
import { sha256 } from '../../crypto';
import type { BitcoinLib, Transaction } from '../../bitcoinLib';

function parseRawTx(rawBytes: Uint8Array): Transaction {
  const parsed = RawTx.decode(rawBytes);
  const nonWitnessSerialization = RawOldTx.encode(parsed);
  const txidHash = sha256(sha256(nonWitnessSerialization));
  const txidBytes = txidHash.slice().reverse();

  return {
    getId: () => hex.encode(txidBytes),
    outs: parsed.outputs.map(o => ({
      script: o.script,
      value: o.amount
    })),
    toBuffer: () => rawBytes
  };
}

export function createScureTransactionAdapter(): BitcoinLib['Transaction'] {
  return {
    fromHex(hexStr: string): Transaction {
      return parseRawTx(hex.decode(hexStr));
    },
    fromBuffer(buf: Uint8Array): Transaction {
      return parseRawTx(buf);
    }
  };
}
