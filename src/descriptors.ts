// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import memoize from 'lodash.memoize';
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
import { encodingLength } from 'varuint-bitcoin';
import type { PartialSig } from 'bip174/src/lib/interfaces';
const { p2sh, p2wpkh, p2pkh, p2pk, p2wsh, p2tr } = payments;
import { BIP32Factory, BIP32API } from 'bip32';
import { ECPairFactory, ECPairAPI } from 'ecpair';

import type {
  TinySecp256k1Interface,
  Preimage,
  TimeConstraints,
  Expansion,
  ExpansionMap,
  ParseKeyExpression
} from './types';

import { finalScriptsFuncFactory, updatePsbt } from './psbt';
import { DescriptorChecksum } from './checksum';

import { parseKeyExpression as globalParseKeyExpression } from './keyExpressions';
import * as RE from './re';
import {
  expandMiniscript as globalExpandMiniscript,
  miniscript2Script,
  satisfyMiniscript
} from './miniscript';

//See "Resource limitations" https://bitcoin.sipa.be/miniscript/
//https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-September/017306.html
const MAX_SCRIPT_ELEMENT_SIZE = 520;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
const MAX_OPS_PER_SCRIPT = 201;

function countNonPushOnlyOPs(script: Buffer): number {
  const decompile = bscript.decompile(script);
  if (!decompile) throw new Error(`Error: cound not decompile ${script}`);
  return decompile.filter(
    op => typeof op === 'number' && op > bscript.OPS['OP_16']!
  ).length;
}

function vectorSize(someVector: Buffer[]): number {
  const length = someVector.length;

  return (
    encodingLength(length) +
    someVector.reduce((sum, witness) => {
      return sum + varSliceSize(witness);
    }, 0)
  );
}

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;

  return encodingLength(length) + length;
}

/**
 * This function will typically return 73; since it assumes a signature size of
 * 72 bytes (this is the max size of a DER encoded signature) and it adds 1
 * extra byte for encoding its length
 */
function signatureSize(
  signature: PartialSig | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
) {
  const length =
    signature === 'DANGEROUSLY_USE_FAKE_SIGNATURES'
      ? 72
      : signature.signature.length;
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

/**
 * Constructs the necessary functions and classes for working with descriptors
 * using an external elliptic curve (ecc) library.
 *
 * Notably, it returns the {@link _Internal_.Output | `Output`} class, which
 * provides methods to create, sign, and finalize PSBTs based on descriptor
 * expressions.
 *
 * While this Factory function includes the `Descriptor` class, note that
 * this class was deprecated in v2.0 in favor of `Output`. For backward
 * compatibility, the `Descriptor` class remains, but using `Output` is advised.
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
    pubkey: Buffer,
    msghash: Buffer,
    signature: Buffer
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

  /**
   * @deprecated
   * @hidden
   * To be removed in version 3.0
   */
  function expand(params: {
    expression: string;
    index?: number;
    checksumRequired?: boolean;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): Expansion;

  /**
   * @hidden
   * To be removed in v3.0 and replaced by the version with the signature that
   * does not accept descriptors
   */
  function expand({
    descriptor,
    expression,
    index,
    checksumRequired = false,
    network = networks.bitcoin,
    allowMiniscriptInP2SH = false
  }: {
    descriptor?: string;
    expression?: string;
    index?: number;
    checksumRequired?: boolean;
    network?: Network;
    allowMiniscriptInP2SH?: boolean;
  }): Expansion {
    if (descriptor && expression)
      throw new Error(`expression param has been deprecated`);
    descriptor = descriptor || expression;
    if (!descriptor) throw new Error(`descriptor not provided`);
    let expandedExpression: string | undefined;
    let miniscript: string | undefined;
    let expansionMap: ExpansionMap | undefined;
    let isSegwit: boolean | undefined;
    let isTaproot: boolean | undefined;
    let expandedMiniscript: string | undefined;
    let payment: Payment | undefined;
    let witnessScript: Buffer | undefined;
    let redeemScript: Buffer | undefined;
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
    //tr(KEY) - taproot - TODO: tr(KEY,TREE) not yet supported
    else if (canonicalExpression.match(RE.reTrSingleKeyAnchored)) {
      isSegwit = true;
      isTaproot = true;
      const keyExpression = canonicalExpression.match(RE.reTaprootKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `tr(${keyExpression})`)
        throw new Error(`Error: invalid expression ${expression}`);
      expandedExpression = 'tr(@0)';
      const pKE = parseKeyExpression({
        keyExpression,
        network,
        isSegwit,
        isTaproot
      });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${expression}`
          );
        payment = p2tr({ internalPubkey: pubkey, network });
        //console.log('TRACE', {
        //  pKE,
        //  pubkey: pubkey?.toString('hex'),
        //  payment,
        //  paymentPubKey: payment.pubkey
        //});
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
    readonly #signersPubKeys: Buffer[];
    readonly #miniscript?: string;
    readonly #witnessScript?: Buffer;
    readonly #redeemScript?: Buffer;
    //isSegwit true if witnesses are needed to the spend coins sent to this descriptor.
    //may be unset because we may get addr(P2SH) which we don't know if they have segwit.
    readonly #isSegwit?: boolean;
    readonly #isTaproot?: boolean;
    readonly #expandedExpression?: string;
    readonly #expandedMiniscript?: string;
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
      signersPubKeys
    }: {
      /**
       * The descriptor string in ASCII format. It may include a "*" to denote an arbitrary index (aka ranged descriptors).
       */
      descriptor: string;

      /**
       * The descriptor's index in the case of a range descriptor (must be an integer >=0).
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
       *
       * For more details on using this parameter, refer to [this Stack Exchange
       * answer](https://bitcoin.stackexchange.com/a/118036/89665).
       */
      signersPubKeys?: Buffer[];
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
      if (expandedResult.redeemScript !== undefined)
        this.#redeemScript = expandedResult.redeemScript;
      if (expandedResult.witnessScript !== undefined)
        this.#witnessScript = expandedResult.witnessScript;

      if (signersPubKeys) {
        this.#signersPubKeys = signersPubKeys;
      } else {
        if (this.#expansionMap) {
          this.#signersPubKeys = Object.values(this.#expansionMap).map(
            keyInfo => {
              const pubkey = keyInfo.pubkey;
              if (!pubkey)
                throw new Error(
                  `Error: could not extract a pubkey from ${descriptor}`
                );
              return pubkey;
            }
          );
        } else {
          //We should only miss expansionMap in addr() expressions:
          if (!expandedResult.canonicalExpression.match(RE.reAddrAnchored)) {
            throw new Error(
              `Error: expansionMap not available for expression ${descriptor} that is not an address`
            );
          }
          this.#signersPubKeys = [this.getScriptPubKey()];
        }
      }
      this.getSequence = memoize(this.getSequence);
      this.getLockTime = memoize(this.getLockTime);
      const getSignaturesKey = (
        signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
      ) =>
        signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES'
          ? signatures
          : signatures
              .map(
                s =>
                  `${s.pubkey.toString('hex')}-${s.signature.toString('hex')}`
              )
              .join('|');
      this.getScriptSatisfaction = memoize(
        this.getScriptSatisfaction,
        // resolver function:
        getSignaturesKey
      );
      this.guessOutput = memoize(this.guessOutput);
      this.inputWeight = memoize(
        this.inputWeight,
        // resolver function:
        (
          isSegwitTx: boolean,
          signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
        ) => {
          const segwitKey = isSegwitTx ? 'segwit' : 'non-segwit';
          const signaturesKey = getSignaturesKey(signatures);
          return `${segwitKey}-${signaturesKey}`;
        }
      );
      this.outputWeight = memoize(this.outputWeight);
    }

    /**
     * Gets the TimeConstraints (nSequence and nLockTime) of the miniscript
     * descriptor as passed in the constructor, just using the expression,
     * the signersPubKeys and preimages.
     *
     * We just need to know which will be the signatures that will be
     * used (signersPubKeys) but final signatures are not necessary for
     * obtaning nLockTime and nSequence.
     *
     * Remember: nSequence and nLockTime are part of the hash that is signed.
     * Thus, they must not change after computing the signatures.
     * When running getScriptSatisfaction, using the final signatures,
     * satisfyMiniscript verifies that the time constraints did not change.
     */
    #getTimeConstraints(): TimeConstraints | undefined {
      const miniscript = this.#miniscript;
      const preimages = this.#preimages;
      const expandedMiniscript = this.#expandedMiniscript;
      const expansionMap = this.#expansionMap;
      const signersPubKeys = this.#signersPubKeys;
      //Create a method. solvePreimages to solve them.
      if (miniscript) {
        if (expandedMiniscript === undefined || expansionMap === undefined)
          throw new Error(
            `Error: cannot get time constraints from not expanded miniscript ${miniscript}`
          );
        //We create some fakeSignatures since we may not have them yet.
        //We only want to retrieve the nLockTime and nSequence of the satisfaction and
        //signatures don't matter
        const fakeSignatures = signersPubKeys.map(pubkey => ({
          pubkey,
          // https://transactionfee.info/charts/bitcoin-script-ecdsa-length/
          signature: Buffer.alloc(72, 0)
        }));
        const { nLockTime, nSequence } = satisfyMiniscript({
          expandedMiniscript,
          expansionMap,
          signatures: fakeSignatures,
          preimages
        });
        return { nLockTime, nSequence };
      } else return undefined;
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
    getScriptPubKey(): Buffer {
      if (!this.#payment.output)
        throw new Error(`Error: could extract output.script from the payment`);
      return this.#payment.output;
    }
    /**
     * Returns the compiled Script Satisfaction if this `Output` was created
     * using a miniscript-based descriptor.
     *
     * The Satisfaction is the unlocking script that fulfills
     * (satisfies) this `Output` and it is derived using the Safisfier algorithm
     * [described here](https://bitcoin.sipa.be/miniscript/).
     *
     * Important: As mentioned above, note that this function only applies to
     * miniscript descriptors.
     */
    getScriptSatisfaction(
      /**
       * An array with all the signatures needed to
       * build the Satisfaction of this miniscript-based `Output`.
       *
       * `signatures` must be passed using this format (pairs of `pubKey/signature`):
       * `interface PartialSig { pubkey: Buffer; signature: Buffer; }`
       *
       *  * Alternatively, if you do not have the signatures, you can use the option
       * `'DANGEROUSLY_USE_FAKE_SIGNATURES'`. This will generate script satisfactions
       * using 72-byte zero-padded signatures. While this can be useful in
       * modules like coinselector that require estimating transaction size before
       * signing, it is critical to understand the risks:
       * - Using this option generales invalid unlocking scripts.
       * - It should NEVER be used with real transactions.
       * - Its primary use is for testing and size estimation purposes only.
       *
       * ⚠️ Warning: Misuse of 'DANGEROUSLY_USE_FAKE_SIGNATURES' can lead to security
       * vulnerabilities, including but not limited to invalid transaction generation.
       * Ensure you fully understand the implications before use.
       *
       */
      signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
    ): Buffer {
      if (signatures === 'DANGEROUSLY_USE_FAKE_SIGNATURES')
        signatures = this.#signersPubKeys.map(pubkey => ({
          pubkey,
          // https://transactionfee.info/charts/bitcoin-script-ecdsa-length/
          signature: Buffer.alloc(72, 0)
        }));
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
      //Note that we pass the nLockTime and nSequence that is deduced
      //using preimages and signersPubKeys.
      //satisfyMiniscript will make sure
      //that the actual solution given, using real signatures, still meets the
      //same nLockTime and nSequence constraints
      const scriptSatisfaction = satisfyMiniscript({
        expandedMiniscript,
        expansionMap,
        signatures,
        preimages: this.#preimages,
        //Here we pass the TimeConstraints obtained using signersPubKeys to
        //verify that the solutions found using the final signatures have not
        //changed
        timeConstraints: {
          nLockTime: this.getLockTime(),
          nSequence: this.getSequence()
        }
      }).scriptSatisfaction;

      if (!scriptSatisfaction)
        throw new Error(`Error: could not produce a valid satisfaction`);
      return scriptSatisfaction;
    }
    /**
     * Gets the nSequence required to fulfill this `Output`.
     */
    getSequence(): number | undefined {
      return this.#getTimeConstraints()?.nSequence;
    }
    /**
     * Gets the nLockTime required to fulfill this `Output`.
     */
    getLockTime(): number | undefined {
      return this.#getTimeConstraints()?.nLockTime;
    }
    /**
     * Gets the witnessScript required to fulfill this `Output`. Only applies to
     * Segwit outputs.
     */
    getWitnessScript(): Buffer | undefined {
      return this.#witnessScript;
    }
    /**
     * Gets the redeemScript required to fullfill this `Output`. Only applies to
     * SH outputs: sh(wpkh), sh(wsh), sh(lockingScript).
     */
    getRedeemScript(): Buffer | undefined {
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
      function guessSH(output: Buffer) {
        try {
          payments.p2sh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessWSH(output: Buffer) {
        try {
          payments.p2wsh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessWPKH(output: Buffer) {
        try {
          payments.p2wpkh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessPKH(output: Buffer) {
        try {
          payments.p2pkh({ output });
          return true;
        } catch (err) {
          void err;
          return false;
        }
      }
      function guessTR(output: Buffer) {
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
     * use a descriptor in the format `sh(MINISCRIPT)` or `tr(MINISCRIPT)`.
     * Note however that tr(MINISCRIPT) is not yet supported for non-single-key
     * expressions.
     */
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
       *  Pass 'DANGEROUSLY_USE_FAKE_SIGNATURES' to assume 72 bytes in length
       *  for ECDSA.
       *  Schnorr signatures are always 64 bytes.
       *  Mainly used for testing.
       */
      signatures: PartialSig[] | 'DANGEROUSLY_USE_FAKE_SIGNATURES'
    ) {
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

      const firstSignature =
        signatures && typeof signatures[0] === 'object'
          ? signatures[0]
          : 'DANGEROUSLY_USE_FAKE_SIGNATURES';

      if (expansion ? expansion.startsWith('pkh(') : isPKH) {
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (sig:73) + (pubkey:34)
          (32 + 4 + 4 + 1 + signatureSize(firstSignature) + 34) * 4 +
          //Segwit:
          (isSegwitTx ? 1 : 0)
        );
      } else if (expansion ? expansion.startsWith('wpkh(') : isWPKH) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1)
          41 * 4 +
          // Segwit: (push_count:1) + (sig:73) + (pubkey:34)
          (1 + signatureSize(firstSignature) + 34)
        );
      } else if (expansion ? expansion.startsWith('sh(wpkh(') : isSH) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1) + (p2wpkh:23)
          //  -> p2wpkh_script: OP_0 OP_PUSH20 <public_key_hash>
          //  -> p2wpkh: (script_len:1) + (script:22)
          64 * 4 +
          // Segwit: (push_count:1) + (sig:73) + (pubkey:34)
          (1 + signatureSize(firstSignature) + 34)
        );
      } else if (expansion?.startsWith('sh(wsh(')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        const witnessScript = this.getWitnessScript();
        if (!witnessScript)
          throw new Error('sh(wsh) must provide witnessScript');
        const payment = payments.p2sh({
          redeem: payments.p2wsh({
            redeem: {
              input: this.getScriptSatisfaction(
                signatures || 'DANGEROUSLY_USE_FAKE_SIGNATURES'
              ),
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
            input: this.getScriptSatisfaction(
              signatures || 'DANGEROUSLY_USE_FAKE_SIGNATURES'
            ),
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
            input: this.getScriptSatisfaction(
              signatures || 'DANGEROUSLY_USE_FAKE_SIGNATURES'
            ),
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
        //when addr(SINGLE_KEY_ADDRESS) or tr(KEY) (single key):
        //TODO: only single-key taproot outputs currently supported
      } else if (isTR && (!expansion || expansion === 'tr(@0)')) {
        if (!isSegwitTx) throw new Error('Should be SegwitTx');
        return (
          // Non-segwit: (txid:32) + (vout:4) + (sequence:4) + (script_len:1)
          41 * 4 +
          // Segwit: (push_count:1) + (sig_length(1) + schnorr_sig(64): 65)
          (1 + 65)
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

    /** @deprecated - Use updatePsbtAsInput instead
     * @hidden
     */
    updatePsbt(params: {
      psbt: Psbt;
      txHex?: string;
      txId?: string;
      value?: number;
      vout: number;
      rbf?: boolean;
    }) {
      this.updatePsbtAsInput(params);
      return params.psbt.data.inputs.length - 1;
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
      value?: number;
      vout: number;
      rbf?: boolean;
    }) {
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
      const index = updatePsbt({
        psbt,
        vout,
        ...(txHex !== undefined ? { txHex } : {}),
        ...(txId !== undefined ? { txId } : {}),
        ...(value !== undefined ? { value } : {}),
        ...(isTaproot
          ? { tapInternalKey: this.getPayment().internalPubkey }
          : {}),
        sequence: this.getSequence(),
        locktime: this.getLockTime(),
        keysInfo: this.#expansionMap ? Object.values(this.#expansionMap) : [],
        scriptPubKey: this.getScriptPubKey(),
        isSegwit,
        witnessScript: this.getWitnessScript(),
        redeemScript: this.getRedeemScript(),
        rbf
      });
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
      }) => this.finalizePsbtInput({ index, psbt, validate });
      return finalizer;
    }

    /**
     * Adds this output as an output of the provided `psbt` with the given
     * value.
     *
     * @param psbt - The Partially Signed Bitcoin Transaction.
     * @param value - The value for the output in satoshis.
     */
    updatePsbtAsOutput({ psbt, value }: { psbt: Psbt; value: number }) {
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
      const eqBuffers = (buf1: Buffer | undefined, buf2: Buffer | undefined) =>
        buf1 instanceof Buffer && buf2 instanceof Buffer
          ? Buffer.compare(buf1, buf2) === 0
          : buf1 === buf2;
      if (
        Buffer.compare(scriptPubKey, this.getScriptPubKey()) !== 0 ||
        (sequenceRBF !== inputSequence && sequenceNoRBF !== inputSequence) ||
        locktime !== psbt.locktime ||
        !eqBuffers(this.getWitnessScript(), input.witnessScript) ||
        !eqBuffers(this.getRedeemScript(), input.redeemScript)
      ) {
        throw new Error(
          `Error: cannot finalize psbt index ${index} since it does not correspond to this descriptor`
        );
      }
    }

    /**
     * Finalizes a PSBT input by adding the necessary unlocking script that satisfies this `Output`'s
     * spending conditions.
     *
     * 🔴 IMPORTANT 🔴
     * It is STRONGLY RECOMMENDED to use the finalizer function returned by
     * {@link _Internal_.Output.updatePsbtAsInput | `updatePsbtAsInput`} instead
     * of calling this method directly.
     * This approach eliminates the need to manage the `Output` instance and the
     * input's index, simplifying the process.
     *
     * The `finalizePsbtInput` method completes a PSBT input by adding the
     * unlocking script (`scriptWitness` or `scriptSig`) that satisfies
     * this `Output`'s spending conditions. Bear in mind that both
     * `scriptSig` and `scriptWitness` incorporate signatures. As such, you
     * should complete all necessary signing operations before calling this
     * method.
     *
     * For each unspent output from a previous transaction that you're
     * referencing in a `psbt` as an input to be spent, apply this method as
     * follows: `output.finalizePsbtInput({ index, psbt })`.
     *
     * It's essential to specify the exact position (or `index`) of the input in
     * the `psbt` that references this unspent `Output`. This `index` should
     * align with the value returned by the `updatePsbtAsInput` method.
     * Note:
     * The `index` corresponds to the position of the input in the `psbt`.
     * To get this index, right after calling `updatePsbtAsInput()`, use:
     * `index = psbt.data.inputs.length - 1`.
     */
    finalizePsbtInput({
      index,
      psbt,
      validate = true
    }: {
      index: number;
      psbt: Psbt;
      /** Runs further test on the validity of the signatures.
       * It speeds down the finalization process but makes sure the psbt will
       * be valid.
       * @default true */
      validate?: boolean | undefined;
    }): void {
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
      //transaction since it is a general Descriptor object. Indices must be kept
      //out of the scope of this class and then passed.

      this.#assertPsbtInput({ index, psbt });
      if (!this.#miniscript) {
        //Use standard finalizers
        psbt.finalizeInput(index);
      } else {
        const signatures = psbt.data.inputs[index]?.partialSig;
        if (!signatures)
          throw new Error(`Error: cannot finalize without signatures`);
        const scriptSatisfaction = this.getScriptSatisfaction(signatures);
        psbt.finalizeInput(
          index,
          finalScriptsFuncFactory(scriptSatisfaction, this.#network)
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
        ...(this.#expansionMap !== undefined
          ? { expansionMap: this.#expansionMap }
          : {})
      };
    }
  }

  /**
   * @hidden
   * @deprecated Use `Output` instead
   */
  class Descriptor extends Output {
    constructor({
      expression,
      ...rest
    }: {
      expression: string;
      index?: number;
      checksumRequired?: boolean;
      allowMiniscriptInP2SH?: boolean;
      network?: Network;
      preimages?: Preimage[];
      signersPubKeys?: Buffer[];
    }) {
      super({ descriptor: expression, ...rest });
    }
  }

  return {
    // deprecated TAG must also be below so it is exported to descriptors.d.ts
    /** @deprecated */ Descriptor,
    Output,
    parseKeyExpression,
    expand,
    ECPair,
    BIP32
  };
}

/** @hidden @deprecated */
type DescriptorConstructor = ReturnType<
  typeof DescriptorsFactory
>['Descriptor'];
/** @hidden  @deprecated */
type DescriptorInstance = InstanceType<DescriptorConstructor>;
export { DescriptorInstance, DescriptorConstructor };

type OutputConstructor = ReturnType<typeof DescriptorsFactory>['Output'];
/**
 * The {@link DescriptorsFactory | `DescriptorsFactory`} function internally
 * creates and returns the {@link _Internal_.Output | `Descriptor`} class.
 * This class is specialized for the provided `TinySecp256k1Interface`.
 * Use `OutputInstance` to declare instances for this class:
 * `const: OutputInstance = new Output();`
 *
 * See the {@link _Internal_.Output | documentation for the internal `Output`
 * class} for a complete list of available methods.
 */
type OutputInstance = InstanceType<OutputConstructor>;
export { OutputInstance, OutputConstructor };
