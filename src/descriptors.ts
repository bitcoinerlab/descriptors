// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import memoize from 'lodash.memoize'; //TODO: make sure this is propoely used
import {
  address,
  networks,
  payments,
  script as bscript,
  Network,
  Transaction,
  Payment,
  Psbt,
  initEccLib
} from 'bitcoinjs-lib';
import {
  tapleafHash,
  witnessStackToScriptWitness
} from './bitcoinjs-lib-internals';
import { encodingLength } from 'varuint-bitcoin';
import { compare, fromHex, toHex } from 'uint8array-tools';
import type { PartialSig } from 'bip174';
const { p2sh, p2wpkh, p2pkh, p2pk, p2wsh, p2tr } = payments;
import { BIP32Factory, BIP32API } from 'bip32';
import { ECPairFactory, ECPairAPI } from 'ecpair';

import type {
  TinySecp256k1Interface,
  Preimage,
  Expansion,
  ExpansionMap,
  ParseKeyExpression
} from './types';

import { finalScriptsFuncFactory, addPsbtInput } from './psbt';
import { DescriptorChecksum } from './checksum';

import { parseKeyExpression as globalParseKeyExpression } from './keyExpressions';
import * as RE from './re';
import {
  expandMiniscript as globalExpandMiniscript,
  miniscript2Script,
  satisfyMiniscript
} from './miniscript';
import { parseTapTreeExpression } from './tapTree';
import type { TapTreeInfoNode, TapTreeNode } from './tapTree';
import {
  buildTaprootLeafPsbtMetadata,
  buildTaprootBip32Derivations,
  buildTapTreeInfo,
  collectTapTreePubkeys,
  normalizeTaprootPubkey,
  tapTreeInfoToScriptTree,
  satisfyTapTree
} from './tapMiniscript';
import type { TaprootLeafSatisfaction } from './tapMiniscript';
import { splitTopLevelComma } from './parseUtils';

//See "Resource limitations" https://bitcoin.sipa.be/miniscript/
//https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-September/017306.html
const MAX_SCRIPT_ELEMENT_SIZE = 520;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
const MAX_OPS_PER_SCRIPT = 201;
const ECDSA_FAKE_SIGNATURE_SIZE = 72;
const TAPROOT_FAKE_SIGNATURE_SIZE = 64;

function countNonPushOnlyOPs(script: Uint8Array): number {
  const decompile = bscript.decompile(script);
  if (!decompile) throw new Error(`Error: cound not decompile ${script}`);
  return decompile.filter(
    op => typeof op === 'number' && op > bscript.OPS['OP_16']!
  ).length;
}

function vectorSize(someVector: Uint8Array[]): number {
  const length = someVector.length;

  return (
    encodingLength(length) +
    someVector.reduce((sum, witness) => {
      return sum + varSliceSize(witness);
    }, 0)
  );
}

function varSliceSize(someScript: Uint8Array): number {
  const length = someScript.length;

  return encodingLength(length) + length;
}

/*
 * Returns a bare descriptor without checksum and particularized for a certain
 * index (if desc was a range descriptor)
 * @hidden
 */
function evaluate({
  descriptor,
  checksumRequired,
  index
}: {
  descriptor: string;
  checksumRequired: boolean;
  index?: number;
}): string {
  if (!descriptor) throw new Error('You must provide a descriptor.');

  const mChecksum = descriptor.match(String.raw`(${RE.reChecksum})$`);
  if (mChecksum === null && checksumRequired === true)
    throw new Error(`Error: descriptor ${descriptor} has not checksum`);
  //evaluatedDescriptor: a bare desc without checksum and particularized for a certain
  //index (if desc was a range descriptor)
  let evaluatedDescriptor = descriptor;
  if (mChecksum !== null) {
    const checksum = mChecksum[0].substring(1); //remove the leading #
    evaluatedDescriptor = descriptor.substring(
      0,
      descriptor.length - mChecksum[0].length
    );
    if (checksum !== DescriptorChecksum(evaluatedDescriptor)) {
      throw new Error(`Error: invalid descriptor checksum for ${descriptor}`);
    }
  }
  if (index !== undefined) {
    const mWildcard = evaluatedDescriptor.match(/\*/g);
    if (mWildcard && mWildcard.length > 0) {
      //From  https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
      //To prevent a combinatorial explosion of the search space, if more than
      //one of the multi() key arguments is a BIP32 wildcard path ending in /* or
      //*', the multi() descriptor only matches multisig scripts with the ith
      //child key from each wildcard path in lockstep, rather than scripts with
      //any combination of child keys from each wildcard path.

      //We extend this reasoning for musig for all cases
      evaluatedDescriptor = evaluatedDescriptor.replaceAll(
        '*',
        index.toString()
      );
    } else
      throw new Error(
        `Error: index passed for non-ranged descriptor: ${descriptor}`
      );
  }
  return evaluatedDescriptor;
}

// Helper: parse sortedmulti(M, k1, k2,...)
function parseSortedMulti(inner: string) {
  // inner: "2,key1,key2,key3"

  const parts = inner.split(',').map(p => p.trim());
  if (parts.length < 2)
    throw new Error(
      `sortedmulti(): must contain M and at least one key: ${inner}`
    );

  const m = Number(parts[0]);
  if (!Number.isInteger(m) || m < 1 || m > 20)
    throw new Error(`sortedmulti(): invalid M=${parts[0]}`);

  const keyExpressions = parts.slice(1);
  if (keyExpressions.length < m)
    throw new Error(`sortedmulti(): M cannot exceed number of keys: ${inner}`);

  if (keyExpressions.length > 20)
    throw new Error(
      `sortedmulti(): descriptors support up to 20 keys (per BIP 380/383).`
    );

  return { m, keyExpressions };
}

function parseTrExpression(expression: string): {
  keyExpression: string;
  treeExpression?: string;
} {
  if (!expression.startsWith('tr(') || !expression.endsWith(')'))
    throw new Error(`Error: invalid descriptor ${expression}`);
  const innerExpression = expression.slice(3, -1).trim();
  if (!innerExpression)
    throw new Error(`Error: invalid descriptor ${expression}`);
  const splitResult = splitTopLevelComma({
    expression: innerExpression,
    onError: () => new Error(`Error: invalid descriptor ${expression}`)
  });
  //if no commas: innerExpression === keyExpression
  if (!splitResult) return { keyExpression: innerExpression };
  return { keyExpression: splitResult.left, treeExpression: splitResult.right };
}

/**
 * Constructs the necessary functions and classes for working with descriptors
 * using an external elliptic curve (ecc) library.
 *
 * Notably, it returns the {@link _Internal_.Output | `Output`} class, which
 * provides methods to create, sign, and finalize PSBTs based on descriptor
 * expressions.
 *
 * The Factory also returns utility methods like `expand` (detailed below)
 * and `parseKeyExpression` (see {@link ParseKeyExpression}).
 *
 * Additionally, for convenience, the function returns `BIP32` and `ECPair`.
 * These are {@link https://github.com/bitcoinjs bitcoinjs-lib} classes designed
 * for managing {@link https://github.com/bitcoinjs/bip32 | `BIP32`} keys and
 * public/private key pairs:
 * {@link https://github.com/bitcoinjs/ecpair | `ECPair`}, respectively.
 *
 * @param {Object} ecc - An object with elliptic curve operations, such as
 * [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1) or
 * [@bitcoinerlab/secp256k1](https://github.com/bitcoinerlab/secp256k1).
 */
export function DescriptorsFactory(ecc: TinySecp256k1Interface) {
  initEccLib(ecc); //Taproot requires initEccLib
  const BIP32: BIP32API = BIP32Factory(ecc);
  const ECPair: ECPairAPI = ECPairFactory(ecc);

  const signatureValidator = (
    pubkey: Uint8Array,
    msghash: Uint8Array,
    signature: Uint8Array
  ): boolean => {
    if (pubkey.length === 32) {
      //x-only
      if (!ecc.verifySchnorr) {
        throw new Error(
          'TinySecp256k1Interface is not initialized properly: verifySchnorr is missing.'
        );
      }
      return ecc.verifySchnorr(msghash, pubkey, signature);
    } else {
      return ECPair.fromPublicKey(pubkey).verify(msghash, signature);
    }
  };

  /**
   * Takes a string key expression (xpub, xprv, pubkey or wif) and parses it
   */
  const parseKeyExpression: ParseKeyExpression = ({
    keyExpression,
    isSegwit,
    isTaproot,
    network = networks.bitcoin
  }) => {
    return globalParseKeyExpression({
      keyExpression,
      network,
      ...(typeof isSegwit === 'boolean' ? { isSegwit } : {}),
      ...(typeof isTaproot === 'boolean' ? { isTaproot } : {}),
      ECPair,
      BIP32
    });
  };

  /**
   * Parses and analyzies a descriptor expression and destructures it into
   * {@link Expansion |its elemental parts}.
   *
   * @throws {Error} Throws an error if the descriptor cannot be parsed or does
   * not conform to the expected format.
   */
  function expand(params: {
    /**
     * The descriptor expression to be expanded.
     */
    descriptor: string;

    /**
     * The descriptor index, if ranged.
     */
    index?: number;

    /**
     * A flag indicating whether the descriptor is required to include a checksum.
     * @defaultValue false
     */
    checksumRequired?: boolean;

    /**
     * The Bitcoin network to use.
     * @defaultValue `networks.bitcoin`
     */
    network?: Network;

    /**
     * Flag to allow miniscript in P2SH.
     * @defaultValue false
     */
    allowMiniscriptInP2SH?: boolean;
  }): Expansion;

  function expand({
    descriptor,
    index,
    checksumRequired = false,
    network = networks.bitcoin,
    allowMiniscriptInP2SH = false
  }: {
    descriptor: string;
    index?: number;
    checksumRequired?: boolean;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): Expansion {
    if (!descriptor) throw new Error(`descriptor not provided`);
    let expandedExpression: string | undefined;
    let miniscript: string | undefined;
    let expansionMap: ExpansionMap | undefined;
    let isSegwit: boolean | undefined;
    let isTaproot: boolean | undefined;
    let expandedMiniscript: string | undefined;
    let tapTreeExpression: string | undefined;
    let tapTree: TapTreeNode | undefined;
    let tapTreeInfo: TapTreeInfoNode | undefined;
    let payment: Payment | undefined;
    let witnessScript: Uint8Array | undefined;
    let redeemScript: Uint8Array | undefined;
    const isRanged = descriptor.indexOf('*') !== -1;

    if (index !== undefined)
      if (!Number.isInteger(index) || index < 0)
        throw new Error(`Error: invalid index ${index}`);

    //Verify and remove checksum (if exists) and
    //particularize range descriptor for index (if desc is range descriptor)
    const canonicalExpression = evaluate({
      descriptor,
      ...(index !== undefined ? { index } : {}),
      checksumRequired
    });
    const isCanonicalRanged = canonicalExpression.indexOf('*') !== -1;

    //addr(ADDR)
    if (canonicalExpression.match(RE.reAddrAnchored)) {
      if (isRanged) throw new Error(`Error: addr() cannot be ranged`);
      const matchedAddress = canonicalExpression.match(RE.reAddrAnchored)?.[1]; //[1]-> whatever is found addr(->HERE<-)
      if (!matchedAddress)
        throw new Error(`Error: could not get an address in ${descriptor}`);
      let output;
      try {
        output = address.toOutputScript(matchedAddress, network);
      } catch (e) {
        void e;
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
      try {
        payment = p2pkh({ output, network });
        isSegwit = false;
        isTaproot = false;
      } catch (e) {
        void e;
      }
      try {
        payment = p2sh({ output, network });
        // It assumes that an addr(SH_ADDRESS) is always a add(SH_WPKH) address
        isSegwit = true;
        isTaproot = false;
      } catch (e) {
        void e;
      }
      try {
        payment = p2wpkh({ output, network });
        isSegwit = true;
        isTaproot = false;
      } catch (e) {
        void e;
      }
      try {
        payment = p2wsh({ output, network });
        isSegwit = true;
        isTaproot = false;
      } catch (e) {
        void e;
      }
      try {
        payment = p2tr({ output, network });
        isSegwit = true;
        isTaproot = true;
      } catch (e) {
        void e;
      }
      if (!payment) {
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
    }
    //pk(KEY)
    else if (canonicalExpression.match(RE.rePkAnchored)) {
      isSegwit = false;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(
        RE.reNonSegwitKeyExp
      )?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `pk(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'pk(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        //Note there exists no address for p2pk, but we can still use the script
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = p2pk({ pubkey, network });
      }
    }
    //pkh(KEY) - legacy
    else if (canonicalExpression.match(RE.rePkhAnchored)) {
      isSegwit = false;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(
        RE.reNonSegwitKeyExp
      )?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `pkh(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'pkh(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = p2pkh({ pubkey, network });
      }
    }
    //sh(wpkh(KEY)) - nested segwit
    else if (canonicalExpression.match(RE.reShWpkhAnchored)) {
      isSegwit = true;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(RE.reSegwitKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `sh(wpkh(${keyExpression}))`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'sh(wpkh(@0))';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = p2sh({ redeem: p2wpkh({ pubkey, network }), network });
        redeemScript = payment.redeem?.output;
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${descriptor}`
          );
      }
    }
    //wpkh(KEY) - native segwit
    else if (canonicalExpression.match(RE.reWpkhAnchored)) {
      isSegwit = true;
      isTaproot = false;
      const keyExpression = canonicalExpression.match(RE.reSegwitKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `wpkh(${keyExpression})`)
        throw new Error(`Error: invalid expression ${descriptor}`);
      expandedExpression = 'wpkh(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        payment = p2wpkh({ pubkey, network });
      }
    }
    // sortedmulti script expressions
    // sh(sortedmulti())
    else if (canonicalExpression.match(RE.reShSortedMultiAnchored)) {
      isSegwit = false;
      isTaproot = false;

      const inner = canonicalExpression.match(RE.reShSortedMultiAnchored)?.[1];
      if (!inner)
        throw new Error(`Error extracting sortedmulti() in ${descriptor}`);

      const { m, keyExpressions } = parseSortedMulti(inner);

      const pKEs = keyExpressions.map(k =>
        parseKeyExpression({ keyExpression: k, network, isSegwit: false })
      );

      const map: ExpansionMap = {};
      pKEs.forEach((pke, i) => (map['@' + i] = pke));
      expansionMap = map;

      expandedExpression =
        'sh(sortedmulti(' +
        [m, ...Object.keys(expansionMap).map(k => k)].join(',') +
        '))';

      if (!isCanonicalRanged) {
        const pubkeys = pKEs.map(p => {
          if (!p.pubkey) throw new Error(`Error: key has no pubkey`);
          return p.pubkey;
        });
        pubkeys.sort((a, b) => compare(a, b));

        const redeem = payments.p2ms({ m, pubkeys, network });
        redeemScript = redeem.output;
        if (!redeemScript) throw new Error(`Error creating redeemScript`);

        payment = payments.p2sh({ redeem, network });
      }
    }
    // wsh(sortedmulti())
    else if (canonicalExpression.match(RE.reWshSortedMultiAnchored)) {
      isSegwit = true;
      isTaproot = false;

      const inner = canonicalExpression.match(RE.reWshSortedMultiAnchored)?.[1];
      if (!inner)
        throw new Error(`Error extracting sortedmulti() in ${descriptor}`);

      const { m, keyExpressions } = parseSortedMulti(inner);

      const pKEs = keyExpressions.map(k =>
        parseKeyExpression({ keyExpression: k, network, isSegwit: true })
      );

      const map: ExpansionMap = {};
      pKEs.forEach((pke, i) => (map['@' + i] = pke));
      expansionMap = map;

      expandedExpression =
        'wsh(sortedmulti(' +
        [m, ...Object.keys(expansionMap).map(k => k)].join(',') +
        '))';

      if (!isCanonicalRanged) {
        const pubkeys = pKEs.map(p => {
          if (!p.pubkey) throw new Error(`Error: key has no pubkey`);
          return p.pubkey;
        });
        pubkeys.sort((a, b) => compare(a, b));

        const redeem = payments.p2ms({ m, pubkeys, network });
        witnessScript = redeem.output;
        if (!witnessScript) throw new Error(`Error computing witnessScript`);

        payment = payments.p2wsh({ redeem, network });
      }
    }
    // sh(wsh(sortedmulti()))
    else if (canonicalExpression.match(RE.reShWshSortedMultiAnchored)) {
      isSegwit = true;
      isTaproot = false;

      const inner = canonicalExpression.match(
        RE.reShWshSortedMultiAnchored
      )?.[1];
      if (!inner)
        throw new Error(`Error extracting sortedmulti() in ${descriptor}`);

      const { m, keyExpressions } = parseSortedMulti(inner);

      const pKEs = keyExpressions.map(k =>
        parseKeyExpression({ keyExpression: k, network, isSegwit: true })
      );

      const map: ExpansionMap = {};
      pKEs.forEach((pke, i) => (map['@' + i] = pke));
      expansionMap = map;

      expandedExpression =
        'sh(wsh(sortedmulti(' +
        [m, ...Object.keys(expansionMap).map(k => k)].join(',') +
        ')))';

      if (!isCanonicalRanged) {
        const pubkeys = pKEs.map(p => {
          if (!p.pubkey) throw new Error(`Error: key has no pubkey`);
          return p.pubkey;
        });
        pubkeys.sort((a, b) => compare(a, b));

        const redeem = payments.p2ms({ m, pubkeys, network });
        const wsh = payments.p2wsh({ redeem, network });

        witnessScript = redeem.output;
        redeemScript = wsh.output;

        payment = payments.p2sh({ redeem: wsh, network });
      }
    }
    //sh(wsh(miniscript))
    else if (canonicalExpression.match(RE.reShWshMiniscriptAnchored)) {
      isSegwit = true;
      isTaproot = false;
      miniscript = canonicalExpression.match(RE.reShWshMiniscriptAnchored)?.[1]; //[1]-> whatever is found sh(wsh(->HERE<-))
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${descriptor}`);
      ({ expandedMiniscript, expansionMap } = expandMiniscript({
        miniscript,
        isSegwit,
        network
      }));
      expandedExpression = `sh(wsh(${expandedMiniscript}))`;

      if (!isCanonicalRanged) {
        const script = miniscript2Script({ expandedMiniscript, expansionMap });
        witnessScript = script;
        if (script.byteLength > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
          throw new Error(
            `Error: script is too large, ${script.byteLength} bytes is larger than ${MAX_STANDARD_P2WSH_SCRIPT_SIZE} bytes`
          );
        }
        const nonPushOnlyOps = countNonPushOnlyOPs(script);
        if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT) {
          throw new Error(
            `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
          );
        }
        payment = p2sh({
          redeem: p2wsh({ redeem: { output: script, network }, network }),
          network
        });
        redeemScript = payment.redeem?.output;
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${descriptor}`
          );
      }
    }
    //sh(miniscript)
    else if (canonicalExpression.match(RE.reShMiniscriptAnchored)) {
      //isSegwit false because we know it's a P2SH of a miniscript and not a
      //P2SH that embeds a witness payment.
      isSegwit = false;
      isTaproot = false;
      miniscript = canonicalExpression.match(RE.reShMiniscriptAnchored)?.[1]; //[1]-> whatever is found sh(->HERE<-)
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${descriptor}`);
      if (
        allowMiniscriptInP2SH === false &&
        //These top-level expressions within sh are allowed within sh.
        //They can be parsed with miniscript2Script, but first we must make sure
        //that other expressions are not accepted (unless forced with allowMiniscriptInP2SH).
        miniscript.search(
          /^(pk\(|pkh\(|wpkh\(|combo\(|multi\(|sortedmulti\(|multi_a\(|sortedmulti_a\()/
        ) !== 0
      ) {
        throw new Error(
          `Error: Miniscript expressions can only be used in wsh`
        );
      }
      ({ expandedMiniscript, expansionMap } = expandMiniscript({
        miniscript,
        isSegwit,
        network
      }));
      expandedExpression = `sh(${expandedMiniscript})`;

      if (!isCanonicalRanged) {
        const script = miniscript2Script({ expandedMiniscript, expansionMap });
        redeemScript = script;
        if (script.byteLength > MAX_SCRIPT_ELEMENT_SIZE) {
          throw new Error(
            `Error: P2SH script is too large, ${script.byteLength} bytes is larger than ${MAX_SCRIPT_ELEMENT_SIZE} bytes`
          );
        }
        const nonPushOnlyOps = countNonPushOnlyOPs(script);
        if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT) {
          throw new Error(
            `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
          );
        }
        payment = p2sh({ redeem: { output: script, network }, network });
      }
    }
    //wsh(miniscript)
    else if (canonicalExpression.match(RE.reWshMiniscriptAnchored)) {
      isSegwit = true;
      isTaproot = false;
      miniscript = canonicalExpression.match(RE.reWshMiniscriptAnchored)?.[1]; //[1]-> whatever is found wsh(->HERE<-)
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${descriptor}`);
      ({ expandedMiniscript, expansionMap } = expandMiniscript({
        miniscript,
        isSegwit,
        network
      }));
      expandedExpression = `wsh(${expandedMiniscript})`;

      if (!isCanonicalRanged) {
        const script = miniscript2Script({ expandedMiniscript, expansionMap });
        witnessScript = script;
        if (script.byteLength > MAX_STANDARD_P2WSH_SCRIPT_SIZE) {
          throw new Error(
            `Error: script is too large, ${script.byteLength} bytes is larger than ${MAX_STANDARD_P2WSH_SCRIPT_SIZE} bytes`
          );
        }
        const nonPushOnlyOps = countNonPushOnlyOPs(script);
        if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT) {
          throw new Error(
            `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
          );
        }
        payment = p2wsh({ redeem: { output: script, network }, network });
      }
    }
    //tr(KEY) or tr(KEY,TREE) - taproot
    else if (canonicalExpression.startsWith('tr(')) {
      isSegwit = true;
      isTaproot = true;
      const { keyExpression, treeExpression } =
        parseTrExpression(canonicalExpression);
      expandedExpression = treeExpression
        ? `tr(@0,${treeExpression})`
        : 'tr(@0)';
      const pKE = parseKeyExpression({
        keyExpression,
        network,
        isSegwit,
        isTaproot
      });
      expansionMap = { '@0': pKE };
      if (treeExpression) {
        tapTreeExpression = treeExpression;
        tapTree = parseTapTreeExpression(treeExpression);
        if (!isCanonicalRanged) {
          tapTreeInfo = buildTapTreeInfo({ tapTree, network, BIP32, ECPair });
        }
      }
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${descriptor}`
          );
        const internalPubkey = normalizeTaprootPubkey(pubkey);
        if (treeExpression) {
          if (!tapTreeInfo)
            throw new Error(`Error: taproot tree info not available`);
          payment = p2tr({
            internalPubkey,
            scriptTree: tapTreeInfoToScriptTree(tapTreeInfo),
            network
          });
        } else {
          payment = p2tr({ internalPubkey, network });
        }
      }
    } else {
      throw new Error(`Error: Could not parse descriptor ${descriptor}`);
    }

    return {
      ...(payment !== undefined ? { payment } : {}),
      ...(expandedExpression !== undefined ? { expandedExpression } : {}),
      ...(miniscript !== undefined ? { miniscript } : {}),
      ...(expansionMap !== undefined ? { expansionMap } : {}),
      ...(isSegwit !== undefined ? { isSegwit } : {}),
      ...(isTaproot !== undefined ? { isTaproot } : {}),
      ...(expandedMiniscript !== undefined ? { expandedMiniscript } : {}),
      ...(tapTreeExpression !== undefined ? { tapTreeExpression } : {}),
      ...(tapTree !== undefined ? { tapTree } : {}),
      ...(tapTreeInfo !== undefined ? { tapTreeInfo } : {}),
      ...(redeemScript !== undefined ? { redeemScript } : {}),
      ...(witnessScript !== undefined ? { witnessScript } : {}),
      isRanged,
      canonicalExpression
    };
  }

  /**
   * Expand a miniscript to a generalized form using variables instead of key
   * expressions. Variables will be of this form: @0, @1, ...
   * This is done so that it can be compiled with compileMiniscript and
   * satisfied with satisfier.
   * Also compute pubkeys from descriptors to use them later.
   */
  function expandMiniscript({
    miniscript,
    isSegwit,
    network = networks.bitcoin
  }: {
    miniscript: string;
    isSegwit: boolean;
    network?: Network;
  }): {
    expandedMiniscript: string;
    expansionMap: ExpansionMap;
  } {
    return globalExpandMiniscript({
      miniscript,
      isSegwit,
      isTaproot: false, //TODO:
      network,
      BIP32,
      ECPair
    });
  }

  /**
   * The `Output` class is the central component for managing descriptors.
   * It facilitates the creation of outputs to receive funds and enables the
   * signing and finalization of PSBTs (Partially Signed Bitcoin Transactions)
   * for spending UTXOs (Unspent Transaction Outputs).
   */
  class Output {
    readonly #payment: Payment;
    readonly #preimages: Preimage[] = [];
    readonly #signersPubKeys?: Uint8Array[];
    readonly #miniscript?: string;
    readonly #witnessScript?: Uint8Array;
    readonly #redeemScript?: Uint8Array;
    //isSegwit true if witnesses are needed to the spend coins sent to this descriptor.
    //may be unset because we may get addr(P2SH) which we don't know if they have segwit.
    readonly #isSegwit?: boolean;
    readonly #isTaproot?: boolean;
    readonly #expandedExpression?: string;
    readonly #expandedMiniscript?: string;
    readonly #tapTreeExpression?: string;
    readonly #tapTree?: TapTreeNode;
    readonly #tapTreeInfo?: TapTreeInfoNode;
    readonly #taprootSpendPath: 'key' | 'script';
    readonly #tapLeaf?: Uint8Array | string;
    readonly #expansionMap?: ExpansionMap;
    readonly #network: Network;
    /**
     * @param options
     * @throws {Error} - when descriptor is invalid
     */
    constructor({
      descriptor,
      index,
      checksumRequired = false,
      allowMiniscriptInP2SH = false,
      network = networks.bitcoin,
      preimages = [],
      signersPubKeys,
      taprootSpendPath,
      tapLeaf
    }: {
      /**
       * The descriptor string in ASCII format. It may include a "*" to denote an arbitrary index (aka ranged descriptors).
       */
      descriptor: string;

      /**
       * The descriptor's index in the case of a range descriptor (must be an integer >=0).
       *
       * This `Output` class always models a concrete spendable output.
       * If the descriptor contains any wildcard (`*`), an `index` is required.
       */
      index?: number;

      /**
       * An optional flag indicating whether the descriptor is required to include a checksum.
       * @defaultValue false
       */
      checksumRequired?: boolean;

      /**
       * A flag indicating whether this instance can parse and generate script satisfactions for sh(miniscript) top-level expressions of miniscripts. This is not recommended.
       * @defaultValue false
       */
      allowMiniscriptInP2SH?: boolean;

      /**
       * One of bitcoinjs-lib [`networks`](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/networks.js) (or another one following the same interface).
       * @defaultValue networks.bitcoin
       */
      network?: Network;

      /**
       * An array of preimages if the miniscript-based descriptor uses them.
       *
       * This info is necessary to finalize Psbts. Leave it `undefined` if your
       * miniscript-based descriptor does not use preimages or you don't know
       * or don't wanto use them.
       *
       * You can also leave it `undefined` if only need to generate the
       * `scriptPubKey` or `address` for a descriptor.
       *
       * @defaultValue `[]`
       */
      preimages?: Preimage[];

      /**
       * An array of the public keys used for signing the transaction when
       * spending the previous output associated with this descriptor.
       *
       * This parameter is only used if the descriptor object is being used to
       * finalize a transaction. It is necessary to specify the spending path
       * when working with miniscript-based expressions that have multiple
       * spending paths.
       *
       * Set this parameter to an array containing the public
       * keys involved in the desired spending path. Leave it `undefined` if you
       * only need to generate the `scriptPubKey` or `address` for a descriptor,
       * or if all the public keys involved in the descriptor will sign the
       * transaction. In the latter case, the satisfier will automatically
       * choose the most optimal spending path (if more than one is available).
       * If omitted, this library assumes that all keys in the miniscript can
       * sign. For taproot script-path spends, keys are inferred per leaf.
       *
       * For more details on using this parameter, refer to [this Stack Exchange
       * answer](https://bitcoin.stackexchange.com/a/118036/89665).
       */
      signersPubKeys?: Uint8Array[];

      /**
       * Taproot spend path policy. Use `key` to force key-path estimation,
       * or `script` to estimate script-path spends.
       *
       * This setting only applies to `tr(KEY,TREE)` descriptors.
       * For `tr(KEY)` descriptors, only key-path is available.
       *
       * When `script` is selected:
       * - if `tapLeaf` is provided, that leaf is used.
       * - if `tapLeaf` is omitted, the satisfier auto-selects the leaf with the
       *   smallest witness among satisfiable candidates.
       *
       * Default policy is `script` for `tr(KEY,TREE)` and `key` for key-only
       * taproot descriptors (`tr(KEY)` and `addr(TR_ADDRESS)`).
       */
      taprootSpendPath?: 'key' | 'script';

      /**
       * Optional taproot leaf selector (tapleaf hash or miniscript string).
       * Only used when taprootSpendPath is `script` and descriptor is
       * `tr(KEY,TREE)`. If omitted, the smallest satisfiable leaf is selected.
       */
      tapLeaf?: Uint8Array | string;
    }) {
      this.#network = network;
      this.#preimages = preimages;
      if (typeof descriptor !== 'string')
        throw new Error(`Error: invalid descriptor type`);

      const expandedResult = expand({
        descriptor,
        ...(index !== undefined ? { index } : {}),
        checksumRequired,
        network,
        allowMiniscriptInP2SH
      });
      const isTaprootDescriptor = expandedResult.isTaproot === true;
      const hasTapTree =
        expandedResult.expandedExpression?.startsWith('tr(@0,') ?? false;
      const resolvedTaprootSpendPath: 'key' | 'script' =
        taprootSpendPath ?? (hasTapTree ? 'script' : 'key');
      if (!isTaprootDescriptor) {
        if (taprootSpendPath !== undefined || tapLeaf !== undefined)
          throw new Error(
            `Error: taprootSpendPath/tapLeaf require a taproot descriptor`
          );
      } else {
        if (taprootSpendPath === 'script' && !hasTapTree)
          throw new Error(
            `Error: taprootSpendPath=script requires a tr(KEY,TREE) descriptor`
          );
        if (resolvedTaprootSpendPath === 'key' && tapLeaf !== undefined)
          throw new Error(
            `Error: tapLeaf cannot be used when taprootSpendPath is key`
          );
        if (tapLeaf !== undefined && !hasTapTree)
          throw new Error(
            `Error: tapLeaf can only be used with tr(KEY,TREE) descriptors`
          );
      }
      if (expandedResult.isRanged && index === undefined)
        throw new Error(`Error: index was not provided for ranged descriptor`);
      if (!expandedResult.payment)
        throw new Error(
          `Error: could not extract a payment from ${descriptor}`
        );

      this.#payment = expandedResult.payment;
      if (expandedResult.expandedExpression !== undefined)
        this.#expandedExpression = expandedResult.expandedExpression;
      if (expandedResult.miniscript !== undefined)
        this.#miniscript = expandedResult.miniscript;
      if (expandedResult.expansionMap !== undefined)
        this.#expansionMap = expandedResult.expansionMap;
      if (expandedResult.isSegwit !== undefined)
        this.#isSegwit = expandedResult.isSegwit;
      if (expandedResult.isTaproot !== undefined)
        this.#isTaproot = expandedResult.isTaproot;
      if (expandedResult.expandedMiniscript !== undefined)
        this.#expandedMiniscript = expandedResult.expandedMiniscript;
      if (expandedResult.tapTreeExpression !== undefined)
        this.#tapTreeExpression = expandedResult.tapTreeExpression;
      if (expandedResult.tapTree !== undefined)
        this.#tapTree = expandedResult.tapTree;
      if (expandedResult.tapTreeInfo !== undefined)
        this.#tapTreeInfo = expandedResult.tapTreeInfo;
      if (expandedResult.redeemScript !== undefined)
        this.#redeemScript = expandedResult.redeemScript;
      if (expandedResult.witnessScript !== undefined)
        this.#witnessScript = expandedResult.witnessScript;

      if (signersPubKeys) this.#signersPubKeys = signersPubKeys;
      this.#taprootSpendPath = resolvedTaprootSpendPath;
      if (tapLeaf !== undefined) this.#tapLeaf = tapLeaf;
      this.getSequence = memoize(this.getSequence);
      this.getLockTime = memoize(this.getLockTime);
      const getSignaturesKey = (
        signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
      ) =>
        signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES'
          ? signatures
          : signatures
              .map(s => `${toHex(s.pubkey)}-${toHex(s.signature)}`)
              .join('|');
      this.guessOutput = memoize(this.guessOutput);
      this.inputWeight = memoize(
        this.inputWeight,
        // resolver function:
        (
          isSegwitTx: boolean,
          signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES',
          options?: {
            taprootSighash?: 'SIGHASH_DEFAULT' | 'non-SIGHASH_DEFAULT';
          }
        ) => {
          const segwitKey = isSegwitTx ? 'segwit' : 'non-segwit';
          const signaturesKey = getSignaturesKey(signatures);
          const taprootSighashKey =
            options?.taprootSighash ?? 'SIGHASH_DEFAULT';
          return `${segwitKey}-${signaturesKey}-taprootSighash:${taprootSighashKey}`;
        }
      );
      this.outputWeight = memoize(this.outputWeight);
    }

    #resolveMiniscriptSignersPubKeys(): Uint8Array[] {
      //If the user did not provide a pubkey subset (signersPubKeys), assume all
      //miniscript pubkeys can sign.
      if (this.#signersPubKeys) return this.#signersPubKeys;
      const expansionMap = this.#expansionMap;
      if (!expansionMap)
        throw new Error(`Error: expansionMap not available for miniscript`);
      return Object.values(expansionMap).map(keyInfo => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey) throw new Error(`Error: miniscript key missing pubkey`);
        return pubkey;
      });
    }

    /**
     * Returns the compiled Script Satisfaction for a miniscript-based Output.
     * The satisfaction is the unlocking script, derived by the Satisfier
     * algorithm (https://bitcoin.sipa.be/miniscript/).
     *
     * This method uses a two-pass flow:
     * 1) Planning: constraints (nLockTime/nSequence) are computed using fake
     *    signatures. This is done since the final solution may not need all the
     *    signatures in signersPubKeys. And we may avoid the user do extra
     *    signing (tedious op with HWW).
     * 2) Signing: the provided signatures are used to build the final
     *    satisfaction, while enforcing the planned constraints so the same
     *    solution is selected. Not all the signatures of signersPubKeys may
     *    be required.
     *
     * The return value includes the satisfaction script and the constraints.
     */

    getScriptSatisfaction(
      /**
       * An array with all the signatures needed to
       * build the Satisfaction of this miniscript-based `Output`.
       *
       * `signatures` must be passed using this format (pairs of `pubKey/signature`):
       * `interface PartialSig { pubkey: Uint8Array; signature: Uint8Array; }`
       */
      signatures: PartialSig[]
    ): {
      scriptSatisfaction: Uint8Array;
      nLockTime: number | undefined;
      nSequence: number | undefined;
    } {
      const miniscript = this.#miniscript;
      const expandedMiniscript = this.#expandedMiniscript;
      const expansionMap = this.#expansionMap;
      if (
        miniscript === undefined ||
        expandedMiniscript === undefined ||
        expansionMap === undefined
      )
        throw new Error(
          `Error: cannot get satisfaction from not expanded miniscript ${miniscript}`
        );
      //This crates the plans using fake signatures
      const constraints = this.#getConstraints();
      return satisfyMiniscript({
        expandedMiniscript,
        expansionMap,
        signatures,
        preimages: this.#preimages,
        //Here we pass the TimeConstraints obtained using signersPubKeys to
        //verify that the solutions found using the final signatures have not
        //changed
        timeConstraints: {
          nLockTime: constraints?.nLockTime,
          nSequence: constraints?.nSequence
        }
      });
    }

    #resolveTapTreeSignersPubKeys(): Uint8Array[] {
      //If the user did not provide a pubkey subset (signersPubKeys), assume all
      //taproot leaf pubkeys can sign.
      const tapTreeInfo = this.#tapTreeInfo;
      if (!tapTreeInfo)
        throw new Error(`Error: taproot tree info not available`);
      const candidatePubkeys = this.#signersPubKeys
        ? this.#signersPubKeys.map(normalizeTaprootPubkey)
        : collectTapTreePubkeys(tapTreeInfo);
      return Array.from(
        new Set(candidatePubkeys.map(pubkey => toHex(pubkey)))
      ).map(hex => fromHex(hex));
    }

    /**
     * Returns the taproot script‑path satisfaction for a tap miniscript
     * descriptor. This mirrors {@link getScriptSatisfaction} and uses the same
     * two‑pass plan/sign flow.
     *
     * In addition to nLockTime/nSequence, it returns the selected tapLeafHash
     * (the leaf chosen during planning) and the leaf’s tapscript.
     */

    getTapScriptSatisfaction(
      /**
       * An array with all the signatures needed to
       * build the Satisfaction of this miniscript-based `Output`.
       *
       * `signatures` must be passed using this format (pairs of `pubKey/signature`):
       * `interface PartialSig { pubkey: Uint8Array; signature: Uint8Array; }`
       */
      signatures: PartialSig[]
    ): TaprootLeafSatisfaction {
      if (this.#taprootSpendPath !== 'script')
        throw new Error(
          `Error: taprootSpendPath is key; script-path satisfaction is not allowed`
        );
      const tapTreeInfo = this.#tapTreeInfo;
      if (!tapTreeInfo)
        throw new Error(`Error: taproot tree info not available`);
      const constraints = this.#getConstraints();
      return satisfyTapTree({
        tapTreeInfo,
        preimages: this.#preimages,
        signatures,
        ...(constraints?.tapLeafHash
          ? { tapLeaf: constraints.tapLeafHash }
          : {}),
        ...(constraints
          ? {
              timeConstraints: {
                nLockTime: constraints.nLockTime,
                nSequence: constraints.nSequence
              }
            }
          : {})
      });
    }

    /**
     * Gets the planning constraints (nSequence and nLockTime) derived from the
     * descriptor, just using the expression, signersPubKeys and preimages
     * (using fake signatures).
     * For taproot script-path spends, it also returns the selected tapLeafHash.
     *
     * We just need to know which will be the signatures that will be
     * used (signersPubKeys) but final signatures are not necessary for
     * obtaning nLockTime and nSequence.
     *
     * Remember: nSequence and nLockTime are part of the hash that is signed.
     * Thus, they must not change after computing the signatures.
     * When running miniscript satisfactions with final signatures,
     * satisfyMiniscript verifies that the time constraints did not change.
     */
    #getConstraints():
      | {
          nLockTime: number | undefined;
          nSequence: number | undefined;
          tapLeafHash: Uint8Array | undefined;
        }
      | undefined {
      const miniscript = this.#miniscript;
      const preimages = this.#preimages;
      const expandedMiniscript = this.#expandedMiniscript;
      const expansionMap = this.#expansionMap;
      const tapTreeInfo = this.#tapTreeInfo;
      //Create a method. solvePreimages to solve them.
      if (miniscript) {
        if (expandedMiniscript === undefined || expansionMap === undefined)
          throw new Error(
            `Error: cannot get time constraints from not expanded miniscript ${miniscript}`
          );
        //We create some fakeSignatures since we may not have them yet.
        //We only want to retrieve the nLockTime and nSequence of the satisfaction and
        //signatures don't matter
        const fakeSignatures = this.#resolveMiniscriptSignersPubKeys().map(
          pubkey => ({
            pubkey,
            signature: new Uint8Array(ECDSA_FAKE_SIGNATURE_SIZE)
          })
        );
        const { nLockTime, nSequence } = satisfyMiniscript({
          expandedMiniscript,
          expansionMap,
          signatures: fakeSignatures,
          preimages
        });
        return { nLockTime, nSequence, tapLeafHash: undefined };
      } else if (tapTreeInfo && this.#taprootSpendPath === 'script') {
        const fakeSignatures = this.#resolveTapTreeSignersPubKeys().map(
          pubkey => ({
            pubkey,
            signature: new Uint8Array(TAPROOT_FAKE_SIGNATURE_SIZE)
          })
        );
        const { nLockTime, nSequence, tapLeafHash } = satisfyTapTree({
          tapTreeInfo,
          preimages: this.#preimages,
          signatures: fakeSignatures,
          ...(this.#tapLeaf !== undefined ? { tapLeaf: this.#tapLeaf } : {})
        });
        return { nLockTime, nSequence, tapLeafHash };
      }

      return undefined;
    }

    /**
     * Creates and returns an instance of bitcoinjs-lib
     * [`Payment`](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/payments/index.ts)'s interface with the `scriptPubKey` of this `Output`.
     */
    getPayment(): Payment {
      return this.#payment;
    }
    /**
     * Returns the Bitcoin Address of this `Output`.
     */
    getAddress(): string {
      if (!this.#payment.address)
        throw new Error(`Error: could extract an address from the payment`);
      return this.#payment.address;
    }
    /**
     * Returns this `Output`'s scriptPubKey.
     */
    getScriptPubKey(): Uint8Array {
      if (!this.#payment.output)
        throw new Error(`Error: could extract output.script from the payment`);
      return this.#payment.output;
    }
    /**
     * Gets the nSequence required to fulfill this `Output`.
     */
    getSequence(): number | undefined {
      return this.#getConstraints()?.nSequence;
    }
    /**
     * Gets the nLockTime required to fulfill this `Output`.
     */
    getLockTime(): number | undefined {
      return this.#getConstraints()?.nLockTime;
    }

    /**
     * Returns the tapleaf hash selected during planning for taproot script-path
     * spends. If signersPubKeys are provided, selection is optimized for those
     * pubkeys. If a specific tapLeaf selector is used in spending calls, this
     * reflects that selection.
     */
    getTapLeafHash(): Uint8Array | undefined {
      return this.#getConstraints()?.tapLeafHash;
    }
    /**
     * Gets the witnessScript required to fulfill this `Output`. Only applies to
     * Segwit outputs.
     */
    getWitnessScript(): Uint8Array | undefined {
      return this.#witnessScript;
    }
    /**
     * Gets the redeemScript required to fullfill this `Output`. Only applies to
     * SH outputs: sh(wpkh), sh(wsh), sh(lockingScript).
     */
    getRedeemScript(): Uint8Array | undefined {
      return this.#redeemScript;
    }
    /**
     * Gets the bitcoinjs-lib [`network`](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/networks.ts) used to create this `Output`.
     */
    getNetwork(): Network {
      return this.#network;
    }
    /**
     * Whether this `Output` is Segwit.
     *
     * *NOTE:* When the descriptor in an input is `addr(address)`, it is assumed
     * that any `addr(SH_TYPE_ADDRESS)` is in fact a Segwit `SH_WPKH`
     * (Script Hash-Witness Public Key Hash).
     * For inputs using arbitrary scripts (not standard addresses),
     * use a descriptor in the format `sh(MINISCRIPT)`.
     *
     */
    isSegwit(): boolean | undefined {
      return this.#isSegwit;
    }

    /**
     * Whether this `Output` is Taproot.
     */
    isTaproot(): boolean | undefined {
      return this.#isTaproot;
    }

    /**
     * Attempts to determine the type of output script by testing it against
     * various payment types.
     *
     * This method tries to identify if the output is one of the following types:
     * - P2SH (Pay to Script Hash)
     * - P2WSH (Pay to Witness Script Hash)
     * - P2WPKH (Pay to Witness Public Key Hash)
     * - P2PKH (Pay to Public Key Hash)
     * - P2TR (Pay to Taproot)
     *
     * @returns An object { isPKH: boolean; isWPKH: boolean; isSH: boolean; isWSH: boolean; isTR: boolean;}
     * with boolean properties indicating the detected output type
     */
    guessOutput() {
      function guessSH(output: Uint8Array) {
        try {
          payments.p2sh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessWSH(output: Uint8Array) {
        try {
          payments.p2wsh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessWPKH(output: Uint8Array) {
        try {
          payments.p2wpkh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessPKH(output: Uint8Array) {
        try {
          payments.p2pkh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessTR(output: Uint8Array) {
        try {
          payments.p2tr({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      const isPKH = guessPKH(this.getScriptPubKey());
      const isWPKH = guessWPKH(this.getScriptPubKey());
      const isSH = guessSH(this.getScriptPubKey());
      const isWSH = guessWSH(this.getScriptPubKey());
      const isTR = guessTR(this.getScriptPubKey());

      if ([isPKH, isWPKH, isSH, isWSH, isTR].filter(Boolean).length > 1)
        throw new Error('Cannot have multiple output types.');

      return { isPKH, isWPKH, isSH, isWSH, isTR };
    }

    // References for inputWeight & outputWeight:
    // https://gist.github.com/junderw/b43af3253ea5865ed52cb51c200ac19c
    // https://bitcoinops.org/en/tools/calc-size/
    // Look for byteLength: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/transaction.ts
    // https://github.com/bitcoinjs/coinselect/blob/master/utils.js
    // https://bitcoin.stackexchange.com/questions/111395/what-is-the-weight-of-a-p2tr-input

    /**
     * Computes the Weight Unit contributions of this Output as if it were the
     * input in a tx.
     *
     * *NOTE:* When the descriptor in an input is `addr(address)`, it is assumed
     * that any `addr(SH_TYPE_ADDRESS)` is in fact a Segwit `SH_WPKH`
     * (Script Hash-Witness Public Key Hash).
     *, Also any `addr(SINGLE_KEY_ADDRESS)` * is assumed to be a single key Taproot
     * address (like those defined in BIP86).
     * For inputs using arbitrary scripts (not standard addresses),
     * use a descriptor in the format `sh(MINISCRIPT)`, `wsh(MINISCRIPT)` or
     * `tr(KEY,TREE)` for taproot script-path expressions.
     */
    // NOTE(taproot-weight): Output instances are concrete. If descriptor has
    // wildcards, constructor requires `index`. No ranged-without-index
    // estimation is attempted here.
    // TODO(taproot-weight): Remaining items:
    // - Annex: not modeled; if annex is used, add witness item sizing.
    // - Taproot sighash defaults: options.taprootSighash currently drives fake
    //   signature sizing; ensure coinselector passes the intended mode.
    // - After PSBT taproot script-path fields are fully populated, add regtest
    //   integration fixtures comparing real tx vsize with inputWeight/outputWeight
    //   estimates for taproot key-path and script-path spends.
    inputWeight(
      /**
       * Indicates if the transaction is a Segwit transaction.
       * If a transaction isSegwitTx, a single byte is then also required for
       * non-witness inputs to encode the length of the empty witness stack:
       * encodeLength(0) + 0 = 1
       * Read more:
       * https://gist.github.com/junderw/b43af3253ea5865ed52cb51c200ac19c?permalink_comment_id=4760512#gistcomment-4760512
       */
      isSegwitTx: boolean,
      /*
       *  Array of `PartialSig`. Each `PartialSig` includes
       *  a public key and its corresponding signature. This parameter
       *  enables the accurate calculation of signature sizes for ECDSA.
       *  Pass 'DANGEROUSLY_USE_FAKE_SIGNATURES' to assume
       *  ECDSA_FAKE_SIGNATURE_SIZE bytes for ECDSA.
       *  For taproot, the fake signature size is controlled by
       *  options.taprootSighash (64 for 'SIGHASH_DEFAULT', 65
       *  for 'non-SIGHASH_DEFAULT'). default value is SIGHASH_DEFAULT
       *  Mainly used for testing.
       */
      signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES',
      /*
       *  Options that affect taproot fake signature sizing.
       *  taprootSighash: 'SIGHASH_DEFAULT' | 'non-SIGHASH_DEFAULT' (default: 'SIGHASH_DEFAULT').
       *  This is only used when signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES'.
       */
      options: {
        taprootSighash?: 'SIGHASH_DEFAULT' | 'non-SIGHASH_DEFAULT';
      } = {
        taprootSighash: 'SIGHASH_DEFAULT'
      }
    ) {
      const taprootSighash = options.taprootSighash ?? 'SIGHASH_DEFAULT';
      if (this.isSegwit() && !isSegwitTx)
        throw new Error(`a tx is segwit if at least one input is segwit`);

      //expand any miniscript-based descriptor. If not miniscript-based, then it's
      //an addr() descriptor. For those, we can only guess their type.
      const expansion = this.expand().expandedExpression;
      const { isPKH, isWPKH, isSH, isTR } = this.guessOutput();
      const errorMsg = `Input type not implemented. Currently supported: pkh(KEY), wpkh(KEY), tr(KEY), \
sh(wpkh(KEY)), sh(wsh(MINISCRIPT)), sh(MINISCRIPT), wsh(MINISCRIPT), \
addr(PKH_ADDRESS), addr(WPKH_ADDRESS), addr(SH_WPKH_ADDRESS), addr(SINGLE_KEY_ADDRESS). \
expansion=${expansion}, isPKH=${isPKH}, isWPKH=${isWPKH}, isSH=${isSH}, isTR=${isTR}.`;
      if (!expansion && !isPKH && !isWPKH && !isSH && !isTR)
        throw new Error(errorMsg);

      const resolveEcdsaSignatureSize = (): number => {
        if (signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES')
          return (
            encodingLength(ECDSA_FAKE_SIGNATURE_SIZE) +
            ECDSA_FAKE_SIGNATURE_SIZE
          );
        if (signatures.length !== 1)
          throw new Error('More than one signture was not expected');
        const singleSignature = signatures[0];
        if (!singleSignature) throw new Error('Signatures not present');
        const length = singleSignature.signature.length;
        return encodingLength(length) + length;
      };
      const resolveMiniscriptSignatures = (): PartialSig[] => {
        if (signatures !== 'DANGEROUSLY_USE_FAKE_SIGNATURES') return signatures;
        return this.#resolveMiniscriptSignersPubKeys().map(pubkey => ({
          pubkey,
          // https://transactionfee.info/charts/bitcoin-script-ecdsa-length/
          signature: new Uint8Array(ECDSA_FAKE_SIGNATURE_SIZE)
        }));
      };

      const taprootFakeSignatureSize =
        taprootSighash === 'SIGHASH_DEFAULT'
          ? TAPROOT_FAKE_SIGNATURE_SIZE
          : TAPROOT_FAKE_SIGNATURE_SIZE + 1;
      const resolveTaprootSignatures = (): PartialSig[] => {
        if (signatures !== 'DANGEROUSLY_USE_FAKE_SIGNATURES') return signatures;
        return this.#resolveTapTreeSignersPubKeys().map(pubkey => ({
          pubkey,
          signature: new Uint8Array(taprootFakeSignatureSize)
        }));
      };
      const resolveTaprootSignatureSize = (): number => {
        let length: number;
        if (signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES') {
          length = taprootFakeSignatureSize;
        } else {
          if (signatures.length !== 1)
            throw new Error('More than one signture was not expected');
          const singleSignature = signatures[0];
          if (!singleSignature) throw new Error('Signatures not present');
          length = singleSignature.signature.length;
        }
        return encodingLength(length) + length;
      };

      const taprootSpendPath = this.#taprootSpendPath;
      const tapLeaf = this.#tapLeaf;

      if (expansion ? expansion.startsWith('pkh(') : isPKH) {
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (sig:73) + (pubkey:34)
          (32 + 4 + 4 + 1 + resolveEcdsaSignatureSize() + 34) * 4 +
          //Segwit:
          (isSegwitTx ? 1 : 0)
        );
      } else if (expansion ? expansion.startsWith('wpkh(') : isWPKH) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1)
          41 * 4 +
          // Segwit: (push_count:1) + (sig:73) + (pubkey:34)
          (1 + resolveEcdsaSignatureSize() + 34)
        );
      } else if (expansion ? expansion.startsWith('sh(wpkh(') : isSH) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (p2wpkh:23)
          //  -> p2wpkh_script: OP_0 OP_PUSH20 <public_key_hash>
          //  -> p2wpkh: (script_len:1) + (script:22)
          64 * 4 +
          // Segwit: (push_count:1) + (sig:73) + (pubkey:34)
          (1 + resolveEcdsaSignatureSize() + 34)
        );
      } else if (expansion?.startsWith('sh(wsh(')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        const witnessScript = this.getWitnessScript();
        if (!witnessScript)
          throw new Error('sh(wsh) must provide witnessScript');
        const payment = payments.p2sh({
          redeem: payments.p2wsh({
            redeem: {
              input: this.getScriptSatisfaction(resolveMiniscriptSignatures())
                .scriptSatisfaction,
              output: witnessScript
            }
          })
        });
        if (!payment || !payment.input || !payment.witness)
          throw new Error('Could not create payment');
        return (
          //Non-segwit
          4 * (40 + varSliceSize(payment.input)) +
          //Segwit
          vectorSize(payment.witness)
        );
      } else if (expansion?.startsWith('sh(')) {
        const redeemScript = this.getRedeemScript();
        if (!redeemScript) throw new Error('sh() must provide redeemScript');
        const payment = payments.p2sh({
          redeem: {
            input: this.getScriptSatisfaction(resolveMiniscriptSignatures())
              .scriptSatisfaction,
            output: redeemScript
          }
        });
        if (!payment || !payment.input)
          throw new Error('Could not create payment');
        if (payment.witness?.length)
          throw new Error(
            'A legacy p2sh payment should not cointain a witness'
          );
        return (
          //Non-segwit
          4 * (40 + varSliceSize(payment.input)) +
          //Segwit:
          (isSegwitTx ? 1 : 0)
        );
      } else if (expansion?.startsWith('wsh(')) {
        const witnessScript = this.getWitnessScript();
        if (!witnessScript) throw new Error('wsh must provide witnessScript');
        const payment = payments.p2wsh({
          redeem: {
            input: this.getScriptSatisfaction(resolveMiniscriptSignatures())
              .scriptSatisfaction,
            output: witnessScript
          }
        });
        if (!payment || !payment.input || !payment.witness)
          throw new Error('Could not create payment');
        return (
          //Non-segwit
          4 * (40 + varSliceSize(payment.input)) +
          //Segwit
          vectorSize(payment.witness)
        );
        // when tr(KEY,TREE): choose key-path or script-path based on
        // constructor taprootSpendPath policy.
      } else if (expansion?.startsWith('tr(@0,')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        if (taprootSpendPath === 'key')
          return 41 * 4 + encodingLength(1) + resolveTaprootSignatureSize();
        const resolvedTapTreeInfo = this.#tapTreeInfo;
        if (!resolvedTapTreeInfo)
          throw new Error(`Error: taproot tree info not available`);
        const taprootSatisfaction = satisfyTapTree({
          tapTreeInfo: resolvedTapTreeInfo,
          preimages: this.#preimages,
          signatures: resolveTaprootSignatures(),
          ...(tapLeaf !== undefined ? { tapLeaf } : {})
        });
        return 41 * 4 + taprootSatisfaction.totalWitnessSize;
      } else if (isTR && (!expansion || expansion === 'tr(@0)')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1)
          41 * 4 +
          // Segwit: (push_count:1) + (sig_length(1) + schnorr_sig(64/65))
          (encodingLength(1) + resolveTaprootSignatureSize())
        );
      } else {
        throw new Error(errorMsg);
      }
    }

    /**
     * Computes the Weight Unit contributions of this Output as if it were the
     * output in a tx.
     */
    outputWeight() {
      //expand any miniscript-based descriptor. If not miniscript-based, then it's
      //an addr() descriptor. For those, we can only guess their type.
      const { isPKH, isWPKH, isSH, isWSH, isTR } = this.guessOutput();
      const errorMsg = `Output type not implemented. Currently supported: pkh=${isPKH}, wpkh=${isWPKH}, tr=${isTR}, sh=${isSH} and wsh=${isWSH}.`;
      if (isPKH) {
        // (p2pkh:26) + (amount:8)
        return 34 * 4;
      } else if (isWPKH) {
        // (p2wpkh:23) + (amount:8)
        return 31 * 4;
      } else if (isSH) {
        // (p2sh:24) + (amount:8)
        return 32 * 4;
      } else if (isWSH) {
        // (p2wsh:35) + (amount:8)
        return 43 * 4;
      } else if (isTR) {
        // (script_pubKey_length:1) + (p2t2(OP_1 OP_PUSH32 <schnorr_public_key>):34) + (amount:8)
        return 43 * 4;
      } else {
        throw new Error(errorMsg);
      }
    }

    /**
     * Sets this output as an input of the provided `psbt` and updates the
     * `psbt` locktime if required by the descriptor.
     *
     * `psbt` and `vout` are mandatory. Include `txHex` as well. The pair
     * `vout` and `txHex` define the transaction and output number this instance
     * pertains to.
     *
     * Though not advised, for Segwit inputs you can pass `txId` and `value`
     * in lieu of `txHex`. If doing so, ensure `value` accuracy to avoid
     * potential fee attacks -
     * [See this issue](https://github.com/bitcoinjs/bitcoinjs-lib/issues/1625).
     *
     * Note: Hardware wallets need the [full `txHex` for Segwit](https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd).
     *
     * When unsure, always use `txHex`, and skip `txId` and `value` for safety.
     *
     * Use `rbf` to mark whether this tx can be replaced with another with
     * higher fee while being in the mempool. Note that a tx will automatically
     * be marked as replacable if a single input requests it.
     * Note that any transaction using a relative timelock (nSequence < 0x80000000)
     * also falls within the RBF range (nSequence < 0xFFFFFFFE), making it
     * inherently replaceable. So don't set `rbf` to false if this is tx uses
     * relative time locks.
     *
     * @returns A finalizer function to be used after signing the `psbt`.
     * This function ensures that this input is properly finalized.
     * The finalizer completes the PSBT input by adding the unlocking script
     * (`scriptWitness` or `scriptSig`) that satisfies this `Output`'s spending
     * conditions. Because these scripts include signatures, you should finish
     * all signing operations before calling the finalizer.
     * The finalizer has this signature:
     *
     * `( { psbt, validate = true } : { psbt: Psbt; validate: boolean | undefined } ) => void`
     *
     */
    updatePsbtAsInput({
      psbt,
      txHex,
      txId,
      value,
      vout, //vector output index
      rbf = true
    }: {
      psbt: Psbt;
      txHex?: string;
      txId?: string;
      value?: bigint;
      vout: number;
      rbf?: boolean;
    }) {
      if (value !== undefined && typeof value !== 'bigint')
        throw new Error(`Error: value must be a bigint`);
      if (value !== undefined && value < 0n)
        throw new Error(`Error: value must be >= 0n`);

      if (txHex === undefined) {
        console.warn(`Warning: missing txHex may allow fee attacks`);
      }
      const isSegwit = this.isSegwit();
      if (isSegwit === undefined) {
        //This should only happen when using addr() expressions
        throw new Error(
          `Error: could not determine whether this is a segwit descriptor`
        );
      }
      const isTaproot = this.isTaproot();
      if (isTaproot === undefined) {
        //This should only happen when using addr() expressions
        throw new Error(
          `Error: could not determine whether this is a taproot descriptor`
        );
      }
      const paymentInternalPubkey = this.getPayment().internalPubkey;
      const tapInternalKey = isTaproot
        ? paymentInternalPubkey
          ? paymentInternalPubkey
          : undefined
        : undefined;
      let tapLeafScript;
      let tapBip32Derivation;
      if (isTaproot && this.#taprootSpendPath === 'script') {
        const tapTreeInfo = this.#tapTreeInfo;
        if (!tapTreeInfo)
          throw new Error(
            `Error: taprootSpendPath=script requires taproot tree info`
          );
        if (!tapInternalKey)
          throw new Error(
            `Error: taprootSpendPath=script requires taproot internal key`
          );
        const taprootLeafMetadata = buildTaprootLeafPsbtMetadata({
          tapTreeInfo,
          internalPubkey: tapInternalKey
        });
        tapLeafScript = taprootLeafMetadata.map(({ leaf, controlBlock }) => ({
          script: leaf.tapScript,
          leafVersion: leaf.version,
          controlBlock
        }));
        const internalKeyInfo = this.#expansionMap?.['@0'];
        if (!internalKeyInfo)
          throw new Error(
            `Error: taproot internal key info not available in expansionMap`
          );
        tapBip32Derivation = buildTaprootBip32Derivations({
          tapTreeInfo,
          internalKeyInfo
        });
      }
      const index = addPsbtInput({
        psbt,
        vout,
        ...(txHex !== undefined ? { txHex } : {}),
        ...(txId !== undefined ? { txId } : {}),
        ...(value !== undefined ? { value } : {}),
        tapInternalKey,
        tapLeafScript,
        tapBip32Derivation,
        sequence: this.getSequence(),
        locktime: this.getLockTime(),
        keysInfo: this.#expansionMap ? Object.values(this.#expansionMap) : [],
        scriptPubKey: this.getScriptPubKey(),
        isSegwit,
        witnessScript: this.getWitnessScript(),
        redeemScript: this.getRedeemScript(),
        rbf
      });
      //The finalizer adds the unlocking script (scriptSig/scriptWitness) once
      //signatures are ready.
      const finalizer = ({
        psbt,
        validate = true
      }: {
        psbt: Psbt;
        /** Runs further test on the validity of the signatures.
         * It speeds down the finalization process but makes sure the psbt will
         * be valid.
         * @default true */
        validate?: boolean | undefined;
      }) => {
        if (
          validate &&
          !psbt.validateSignaturesOfInput(index, signatureValidator)
        ) {
          throw new Error(`Error: invalid signatures on input ${index}`);
        }
        //An index must be passed since finding the index in the psbt cannot be
        //done:
        //Imagine the case where you received money twice to
        //the same miniscript-based address. You would have the same scriptPubKey,
        //same sequences, ... The descriptor does not store the hash of the previous
        //transaction since it is a general Output instance. Indices must be kept
        //out of the scope of this class and then passed.

        this.#assertPsbtInput({ index, psbt });
        if (
          this.#isTaproot &&
          this.#taprootSpendPath === 'script' &&
          !this.#tapTreeInfo
        )
          throw new Error(
            `Error: taprootSpendPath=script requires taproot tree info`
          );
        if (this.#tapTreeInfo && this.#taprootSpendPath === 'script') {
          const input = psbt.data.inputs[index];
          const tapLeafScript = input?.tapLeafScript;
          if (!tapLeafScript || tapLeafScript.length === 0)
            throw new Error(
              `Error: cannot finalize taproot script-path without tapLeafScript`
            );
          const tapScriptSig = input?.tapScriptSig;
          if (!tapScriptSig || tapScriptSig.length === 0)
            throw new Error(
              `Error: cannot finalize taproot script-path without tapScriptSig`
            );
          const taprootSatisfaction =
            this.getTapScriptSatisfaction(tapScriptSig);
          const matchingLeaf = tapLeafScript.find(
            leafScript =>
              compare(
                tapleafHash({
                  output: leafScript.script,
                  version: leafScript.leafVersion
                }),
                taprootSatisfaction.tapLeafHash
              ) === 0
          );
          if (!matchingLeaf)
            throw new Error(
              `Error: tapLeafScript does not match planned tapLeafHash`
            );
          if (
            compare(matchingLeaf.script, taprootSatisfaction.leaf.tapScript) !==
              0 ||
            matchingLeaf.leafVersion !== taprootSatisfaction.leaf.version
          )
            throw new Error(
              `Error: tapLeafScript does not match planned leaf script`
            );
          const witness = [
            ...taprootSatisfaction.stackItems,
            matchingLeaf.script,
            matchingLeaf.controlBlock
          ];
          const finalScriptWitness = witnessStackToScriptWitness(witness);
          psbt.finalizeTaprootInput(
            index,
            taprootSatisfaction.tapLeafHash,
            () => ({ finalScriptWitness })
          );
        } else if (!this.#miniscript) {
          //Use standard finalizers
          psbt.finalizeInput(index);
        } else {
          const signatures = psbt.data.inputs[index]?.partialSig;
          if (!signatures)
            throw new Error(`Error: cannot finalize without signatures`);
          const { scriptSatisfaction } = this.getScriptSatisfaction(signatures);
          psbt.finalizeInput(
            index,
            finalScriptsFuncFactory(scriptSatisfaction, this.#network)
          );
        }
      };
      return finalizer;
    }

    /**
     * Adds this output as an output of the provided `psbt` with the given
     * value.
     * @param params - The parameters for the method.
     * @param params.psbt - The Partially Signed Bitcoin Transaction.
     * @param params.value - The value for the output in satoshis.
     */
    updatePsbtAsOutput({ psbt, value }: { psbt: Psbt; value: bigint }) {
      if (typeof value !== 'bigint')
        throw new Error(`Error: value must be a bigint`);
      if (value < 0n) throw new Error(`Error: value must be >= 0n`);
      psbt.addOutput({ script: this.getScriptPubKey(), value });
    }

    #assertPsbtInput({ psbt, index }: { psbt: Psbt; index: number }): void {
      const input = psbt.data.inputs[index];
      const txInput = psbt.txInputs[index];
      if (!input || !txInput)
        throw new Error(`Error: invalid input or txInput`);
      const { sequence: inputSequence, index: vout } = txInput;
      let scriptPubKey;
      if (input.witnessUtxo) scriptPubKey = input.witnessUtxo.script;
      else {
        if (!input.nonWitnessUtxo)
          throw new Error(
            `Error: input should have either witnessUtxo or nonWitnessUtxo`
          );
        const tx = Transaction.fromBuffer(input.nonWitnessUtxo);
        const out = tx.outs[vout];
        if (!out) throw new Error(`Error: utxo should exist`);
        scriptPubKey = out.script;
      }
      const locktime = this.getLockTime() || 0;
      const sequence = this.getSequence();
      //We don't know whether the user opted for RBF or not. So check that
      //at least one of the 2 sequences matches.
      const sequenceNoRBF =
        sequence !== undefined
          ? sequence
          : locktime === 0
            ? 0xffffffff
            : 0xfffffffe;
      const sequenceRBF = sequence !== undefined ? sequence : 0xfffffffd;
      const eqBytes = (
        bytes1: Uint8Array | undefined,
        bytes2: Uint8Array | undefined
      ) =>
        bytes1 === undefined || bytes2 === undefined
          ? bytes1 === bytes2
          : compare(bytes1, bytes2) === 0;
      if (
        compare(scriptPubKey, this.getScriptPubKey()) !== 0 ||
        (sequenceRBF !== inputSequence && sequenceNoRBF !== inputSequence) ||
        locktime !== psbt.locktime ||
        !eqBytes(this.getWitnessScript(), input.witnessScript) ||
        !eqBytes(this.getRedeemScript(), input.redeemScript)
      ) {
        throw new Error(
          `Error: cannot finalize psbt index ${index} since it does not correspond to this descriptor`
        );
      }
    }

    /**
     * Decomposes the descriptor used to form this `Output` into its elemental
     * parts. See {@link ExpansionMap ExpansionMap} for a detailed explanation.
     */
    expand() {
      return {
        ...(this.#expandedExpression !== undefined
          ? { expandedExpression: this.#expandedExpression }
          : {}),
        ...(this.#miniscript !== undefined
          ? { miniscript: this.#miniscript }
          : {}),
        ...(this.#expandedMiniscript !== undefined
          ? { expandedMiniscript: this.#expandedMiniscript }
          : {}),
        ...(this.#tapTreeExpression !== undefined
          ? { tapTreeExpression: this.#tapTreeExpression }
          : {}),
        ...(this.#tapTree !== undefined ? { tapTree: this.#tapTree } : {}),
        ...(this.#tapTreeInfo !== undefined
          ? { tapTreeInfo: this.#tapTreeInfo }
          : {}),
        ...(this.#expansionMap !== undefined
          ? { expansionMap: this.#expansionMap }
          : {})
      };
    }
  }

  return {
    Output,
    parseKeyExpression,
    expand,
    ECPair,
    BIP32
  };
}

type OutputConstructor = ReturnType<typeof DescriptorsFactory>['Output'];
/**
 * The {@link DescriptorsFactory | `DescriptorsFactory`} function internally
 * creates and returns the {@link _Internal_.Output | `Output`} class.
 * This class is specialized for the provided `TinySecp256k1Interface`.
 * Use `OutputInstance` to declare instances for this class:
 * `const: OutputInstance = new Output();`
 *
 * See the {@link _Internal_.Output | documentation for the internal `Output`
 * class} for a complete list of available methods.
 */
type OutputInstance = InstanceType<OutputConstructor>;
export { OutputInstance, OutputConstructor };
