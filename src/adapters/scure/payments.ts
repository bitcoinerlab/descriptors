// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
import type { TaprootScriptTree } from '@scure/btc-signer/payment.js';
import { compare } from 'uint8array-tools';
import type { BitcoinLib, Payment, Taptree } from '../../bitcoinLib';
import { networks, type Network } from '../../networks';
import { toBtcSignerNetwork } from './common';
import { toStack } from './script';

function convertTaptree(tree: Taptree): TaprootScriptTree {
  if (Array.isArray(tree))
    return [convertTaptree(tree[0]), convertTaptree(tree[1])];
  return { script: tree.output, leafVersion: tree.version ?? 0xc0 };
}

function decodeOutputWithAddress(
  output: Uint8Array,
  expectedType: 'pkh' | 'sh' | 'wpkh' | 'wsh',
  net: ReturnType<typeof toBtcSignerNetwork>
) {
  const decoded = btc.OutScript.decode(output);
  if (decoded.type !== expectedType) return undefined;
  return { output, address: btc.Address(net).encode(decoded) };
}

export function createScurePaymentsAdapter(): BitcoinLib['payments'] {
  return {
    p2pk(a: { pubkey: Uint8Array; network?: Network }) {
      if (!a.pubkey) throw new Error('p2pk requires pubkey');
      const net = toBtcSignerNetwork(a.network ?? networks.bitcoin);
      const result = btc.p2pk(a.pubkey, net);
      return { output: result.script, pubkey: a.pubkey };
    },

    p2pkh(a: {
      pubkey?: Uint8Array;
      hash?: Uint8Array;
      output?: Uint8Array;
      network?: Network;
    }) {
      const net = toBtcSignerNetwork(a.network ?? networks.bitcoin);
      if (a.pubkey) {
        const result = btc.p2pkh(a.pubkey, net);
        return {
          output: result.script,
          address: result.address,
          pubkey: a.pubkey
        };
      }
      if (a.hash)
        throw new Error(
          'p2pkh({ hash }) is not supported in the scure adapter. Use pubkey or output.'
        );
      if (a.output) {
        const payment = decodeOutputWithAddress(a.output, 'pkh', net);
        if (payment) return payment;
      }
      throw new Error('p2pkh requires pubkey or output');
    },

    p2sh(a: { redeem?: Payment; output?: Uint8Array; network?: Network }) {
      if (a.network && a.redeem?.network && a.network !== a.redeem.network)
        throw new TypeError('Network mismatch');

      const net = toBtcSignerNetwork(
        a.network ?? a.redeem?.network ?? networks.bitcoin
      );
      if (a.redeem?.output) {
        const innerScript = a.redeem.output;
        if (innerScript.length > 520) {
          throw new Error('Redeem.output unspendable if larger than 520 bytes');
        }
        const input = btc.Script.encode(
          a.redeem.input
            ? [...toStack(a.redeem.input), innerScript]
            : [innerScript]
        );
        const result = btc.p2sh({ type: 'unknown', script: innerScript }, net);
        const payment: Payment = {
          output: result.script,
          address: result.address,
          redeem: { ...a.redeem, output: innerScript },
          input
        };
        if (a.redeem.witness) payment.witness = a.redeem.witness;
        return payment;
      }
      if (a.output) {
        const payment = decodeOutputWithAddress(a.output, 'sh', net);
        if (payment) return payment;
      }
      throw new Error('p2sh requires redeem.output or output');
    },

    p2wpkh(a: {
      pubkey?: Uint8Array;
      hash?: Uint8Array;
      output?: Uint8Array;
      network?: Network;
    }) {
      const net = toBtcSignerNetwork(a.network ?? networks.bitcoin);
      if (a.pubkey) {
        const result = btc.p2wpkh(a.pubkey, net);
        return {
          output: result.script,
          address: result.address,
          pubkey: a.pubkey
        };
      }
      if (a.hash)
        throw new Error(
          'p2wpkh({ hash }) is not supported in the scure adapter. Use pubkey or output.'
        );
      if (a.output) {
        const payment = decodeOutputWithAddress(a.output, 'wpkh', net);
        if (payment) return payment;
      }
      throw new Error('p2wpkh requires pubkey or output');
    },

    p2wsh(a: { redeem?: Payment; output?: Uint8Array; network?: Network }) {
      if (a.network && a.redeem?.network && a.network !== a.redeem.network)
        throw new TypeError('Network mismatch');

      const net = toBtcSignerNetwork(
        a.network ?? a.redeem?.network ?? networks.bitcoin
      );
      if (a.redeem?.output) {
        const innerScript = a.redeem.output;
        const witness = a.redeem.input
          ? [...toStack(a.redeem.input), innerScript]
          : a.redeem.witness
            ? [...a.redeem.witness, innerScript]
            : undefined;
        const result = btc.p2wsh({ type: 'unknown', script: innerScript }, net);
        const payment: Payment = {
          output: result.script,
          address: result.address,
          redeem: {
            ...a.redeem,
            output: innerScript,
            input: new Uint8Array(0)
          },
          input: new Uint8Array(0)
        };
        if (witness) payment.witness = witness;
        return payment;
      }
      if (a.output) {
        const payment = decodeOutputWithAddress(a.output, 'wsh', net);
        if (payment) return payment;
      }
      throw new Error('p2wsh requires redeem.output or output');
    },

    p2ms(a: { m: number; pubkeys: Uint8Array[]; network?: Network }) {
      const result = btc.p2ms(a.m, a.pubkeys);
      return { output: result.script };
    },

    p2tr(a: {
      internalPubkey?: Uint8Array;
      scriptTree?: Taptree;
      redeem?: { output: Uint8Array; redeemVersion?: number };
      output?: Uint8Array;
      network?: Network;
    }) {
      const net = toBtcSignerNetwork(a.network ?? networks.bitcoin);
      if (a.internalPubkey) {
        if (a.scriptTree) {
          const scriptTree = convertTaptree(a.scriptTree);
          const treeResult = btc.p2tr(a.internalPubkey, scriptTree, net, true);
          const payment: Payment = {
            output: treeResult.script,
            address: treeResult.address,
            internalPubkey: a.internalPubkey,
            pubkey: treeResult.tweakedPubkey
          };

          if (a.redeem?.output) {
            const redeemVersion = a.redeem.redeemVersion ?? 0xc0;
            for (const [
              controlBlock,
              scriptWithVersion
            ] of treeResult.tapLeafScript ?? []) {
              const leafVersion =
                scriptWithVersion[scriptWithVersion.length - 1] ?? 0xc0;
              const leafScript = scriptWithVersion.subarray(0, -1);
              if (
                compare(leafScript, a.redeem.output) === 0 &&
                leafVersion === redeemVersion
              ) {
                payment.witness = [
                  leafScript,
                  btc.TaprootControlBlock.encode(controlBlock)
                ];
                break;
              }
            }
          }
          return payment;
        }

        const keyResult = btc.p2tr(a.internalPubkey, undefined, net);
        return {
          output: keyResult.script,
          address: keyResult.address,
          internalPubkey: a.internalPubkey,
          pubkey: keyResult.tweakedPubkey
        };
      }
      if (a.output) {
        const decoded = btc.OutScript.decode(a.output);
        if (decoded.type === 'tr') {
          const address = btc.Address(net).encode(decoded);
          return { output: a.output, address, pubkey: decoded.pubkey };
        }
      }
      throw new Error('p2tr requires internalPubkey or output');
    }
  };
}
