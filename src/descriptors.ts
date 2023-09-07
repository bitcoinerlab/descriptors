// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  address,
  networks,
  payments,
  script as bscript,
  Network,
  Transaction,
  Payment,
  Psbt
} from 'bitcoinjs-lib';
import type { PartialSig } from 'bip174/src/lib/interfaces';
const { p2sh, p2wpkh, p2pkh, p2pk, p2wsh, p2tr } = payments;
import { BIP32Factory, BIP32API } from 'bip32';
import { ECPairFactory, ECPairAPI } from 'ecpair';

import type {
  TinySecp256k1Interface,
  Preimage,
  TimeConstraints,
  ExpansionMap,
  Expand,
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

/*
 * Returns a bare descriptor without checksum and particularized for a certain
 * index (if desc was a range descriptor)
 */
function evaluate({
  expression,
  checksumRequired,
  index
}: {
  expression: string;
  checksumRequired: boolean;
  index?: number;
}): string {
  const mChecksum = expression.match(String.raw`(${RE.reChecksum})$`);
  if (mChecksum === null && checksumRequired === true)
    throw new Error(`Error: descriptor ${expression} has not checksum`);
  //evaluatedExpression: a bare desc without checksum and particularized for a certain
  //index (if desc was a range descriptor)
  let evaluatedExpression = expression;
  if (mChecksum !== null) {
    const checksum = mChecksum[0].substring(1); //remove the leading #
    evaluatedExpression = expression.substring(
      0,
      expression.length - mChecksum[0].length
    );
    if (checksum !== DescriptorChecksum(evaluatedExpression)) {
      throw new Error(`Error: invalid descriptor checksum for ${expression}`);
    }
  }
  if (index !== undefined) {
    const mWildcard = evaluatedExpression.match(/\*/g);
    if (mWildcard && mWildcard.length > 0) {
      //From  https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
      //To prevent a combinatorial explosion of the search space, if more than
      //one of the multi() key arguments is a BIP32 wildcard path ending in /* or
      //*', the multi() expression only matches multisig scripts with the ith
      //child key from each wildcard path in lockstep, rather than scripts with
      //any combination of child keys from each wildcard path.

      //We extend this reasoning for musig for all cases
      evaluatedExpression = evaluatedExpression.replaceAll(
        '*',
        index.toString()
      );
    } else
      throw new Error(
        `Error: index passed for non-ranged descriptor: ${expression}`
      );
  }
  return evaluatedExpression;
}

/**
 * Builds the functions needed to operate with descriptors using an external elliptic curve (ecc) library.
 * @param {Object} ecc - an object containing elliptic curve operations, such as [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1) or [@bitcoinerlab/secp256k1](https://github.com/bitcoinerlab/secp256k1).
 */
export function DescriptorsFactory(ecc: TinySecp256k1Interface) {
  const BIP32: BIP32API = BIP32Factory(ecc);
  const ECPair: ECPairAPI = ECPairFactory(ecc);
  const signatureValidator = (
    pubkey: Buffer,
    msghash: Buffer,
    signature: Buffer
  ): boolean => ECPair.fromPublicKey(pubkey).verify(msghash, signature);

  /**
   * Takes a string key expression (xpub, xprv, pubkey or wif) and parses it
   */
  const parseKeyExpression: ParseKeyExpression = ({
    keyExpression,
    isSegwit,
    network = networks.bitcoin
  }) => {
    return globalParseKeyExpression({
      keyExpression,
      network,
      ...(typeof isSegwit === 'boolean' ? { isSegwit } : {}),
      ECPair,
      BIP32
    });
  };

  /**
   * Takes a descriptor (expression) and expands it to its corresponding Bitcoin script and other relevant details.
   *
   * @throws {Error} Throws an error if the descriptor cannot be parsed or does not conform to the expected format.
   */
  const expand: Expand = ({
    expression,
    index,
    checksumRequired = false,
    network = networks.bitcoin,
    allowMiniscriptInP2SH = false
  }) => {
    let expandedExpression: string | undefined;
    let miniscript: string | undefined;
    let expansionMap: ExpansionMap | undefined;
    let isSegwit: boolean | undefined;
    let expandedMiniscript: string | undefined;
    let payment: Payment | undefined;
    let witnessScript: Buffer | undefined;
    let redeemScript: Buffer | undefined;
    const isRanged = expression.indexOf('*') !== -1;

    if (index !== undefined)
      if (!Number.isInteger(index) || index < 0)
        throw new Error(`Error: invalid index ${index}`);

    //Verify and remove checksum (if exists) and
    //particularize range descriptor for index (if desc is range descriptor)
    const canonicalExpression = evaluate({
      expression,
      ...(index !== undefined ? { index } : {}),
      checksumRequired
    });
    const isCanonicalRanged = canonicalExpression.indexOf('*') !== -1;

    //addr(ADDR)
    if (canonicalExpression.match(RE.reAddrAnchored)) {
      if (isRanged) throw new Error(`Error: addr() cannot be ranged`);
      const matchedAddress = canonicalExpression.match(RE.reAddrAnchored)?.[1]; //[1]-> whatever is found addr(->HERE<-)
      if (!matchedAddress)
        throw new Error(`Error: could not get an address in ${expression}`);
      let output;
      try {
        output = address.toOutputScript(matchedAddress, network);
      } catch (e) {
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
      try {
        payment = p2pkh({ output, network });
      } catch (e) {}
      try {
        payment = p2sh({ output, network });
      } catch (e) {}
      try {
        payment = p2wpkh({ output, network });
      } catch (e) {}
      try {
        payment = p2wsh({ output, network });
      } catch (e) {}
      try {
        payment = p2tr({ output, network });
      } catch (e) {}
      if (!payment) {
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
    }
    //pk(KEY)
    else if (canonicalExpression.match(RE.rePkAnchored)) {
      isSegwit = false;
      const keyExpression = canonicalExpression.match(RE.reKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `pk(${keyExpression})`)
        throw new Error(`Error: invalid expression ${expression}`);
      expandedExpression = 'pk(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        //Note there exists no address for p2pk, but we can still use the script
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${expression}`
          );
        payment = p2pk({ pubkey, network });
      }
    }
    //pkh(KEY) - legacy
    else if (canonicalExpression.match(RE.rePkhAnchored)) {
      isSegwit = false;
      const keyExpression = canonicalExpression.match(RE.reKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `pkh(${keyExpression})`)
        throw new Error(`Error: invalid expression ${expression}`);
      expandedExpression = 'pkh(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${expression}`
          );
        payment = p2pkh({ pubkey, network });
      }
    }
    //sh(wpkh(KEY)) - nested segwit
    else if (canonicalExpression.match(RE.reShWpkhAnchored)) {
      isSegwit = true;
      const keyExpression = canonicalExpression.match(RE.reKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `sh(wpkh(${keyExpression}))`)
        throw new Error(`Error: invalid expression ${expression}`);
      expandedExpression = 'sh(wpkh(@0))';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${expression}`
          );
        payment = p2sh({ redeem: p2wpkh({ pubkey, network }), network });
        redeemScript = payment.redeem?.output;
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${expression}`
          );
      }
    }
    //wpkh(KEY) - native segwit
    else if (canonicalExpression.match(RE.reWpkhAnchored)) {
      isSegwit = true;
      const keyExpression = canonicalExpression.match(RE.reKeyExp)?.[0];
      if (!keyExpression)
        throw new Error(`Error: keyExpression could not me extracted`);
      if (canonicalExpression !== `wpkh(${keyExpression})`)
        throw new Error(`Error: invalid expression ${expression}`);
      expandedExpression = 'wpkh(@0)';
      const pKE = parseKeyExpression({ keyExpression, network, isSegwit });
      expansionMap = { '@0': pKE };
      if (!isCanonicalRanged) {
        const pubkey = pKE.pubkey;
        if (!pubkey)
          throw new Error(
            `Error: could not extract a pubkey from ${expression}`
          );
        payment = p2wpkh({ pubkey, network });
      }
    }
    //sh(wsh(miniscript))
    else if (canonicalExpression.match(RE.reShWshMiniscriptAnchored)) {
      isSegwit = true;
      miniscript = canonicalExpression.match(RE.reShWshMiniscriptAnchored)?.[1]; //[1]-> whatever is found sh(wsh(->HERE<-))
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${expression}`);
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
            `Error: could not calculate redeemScript for ${expression}`
          );
      }
    }
    //sh(miniscript)
    else if (canonicalExpression.match(RE.reShMiniscriptAnchored)) {
      //isSegwit false because we know it's a P2SH of a miniscript and not a
      //P2SH that embeds a witness payment.
      isSegwit = false;
      miniscript = canonicalExpression.match(RE.reShMiniscriptAnchored)?.[1]; //[1]-> whatever is found sh(->HERE<-)
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${expression}`);
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
      miniscript = canonicalExpression.match(RE.reWshMiniscriptAnchored)?.[1]; //[1]-> whatever is found wsh(->HERE<-)
      if (!miniscript)
        throw new Error(`Error: could not get miniscript in ${expression}`);
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
    } else {
      throw new Error(`Error: Could not parse descriptor ${expression}`);
    }

    return {
      ...(payment !== undefined ? { payment } : {}),
      ...(expandedExpression !== undefined ? { expandedExpression } : {}),
      ...(miniscript !== undefined ? { miniscript } : {}),
      ...(expansionMap !== undefined ? { expansionMap } : {}),
      ...(isSegwit !== undefined ? { isSegwit } : {}),
      ...(expandedMiniscript !== undefined ? { expandedMiniscript } : {}),
      ...(redeemScript !== undefined ? { redeemScript } : {}),
      ...(witnessScript !== undefined ? { witnessScript } : {}),
      isRanged,
      canonicalExpression
    };
  };

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
      network,
      BIP32,
      ECPair
    });
  }

  class Descriptor {
    readonly #payment: Payment;
    readonly #preimages: Preimage[] = [];
    readonly #signersPubKeys: Buffer[];
    readonly #miniscript?: string;
    readonly #witnessScript?: Buffer;
    readonly #redeemScript?: Buffer;
    //isSegwit true if witnesses are needed to the spend coins sent to this descriptor.
    //may be unset because we may get addr(P2SH) which we don't know if they have segwit.
    readonly #isSegwit?: boolean;
    readonly #expandedExpression?: string;
    readonly #expandedMiniscript?: string;
    readonly #expansionMap?: ExpansionMap;
    readonly #network: Network;
    /**
     * @param options
     * @throws {Error} - when descriptor is invalid
     */
    constructor({
      expression,
      index,
      checksumRequired = false,
      allowMiniscriptInP2SH = false,
      network = networks.bitcoin,
      preimages = [],
      signersPubKeys
    }: {
      /**
       * The descriptor string in ASCII format. It may include a "*" to denote an arbitrary index.
       */
      expression: string;

      /**
       * The descriptor's index in the case of a range descriptor (must be an integer >=0).
       */
      index?: number;

      /**
       * A flag indicating whether the descriptor is required to include a checksum.
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
       * An array of preimages. This info is necessary to finalize Psbts.
       * @defaultValue `[]`
       */
      preimages?: Preimage[];

      /**
       * An array of the public keys used for signing the transaction when spending the output associated with this descriptor. This parameter is only used if the descriptor object is being used to finalize a transaction. It is necessary to specify the spending path when working with miniscript-based expressions that have multiple spending paths. Set this parameter to an array containing the public keys involved in the desired spending path. Leave it `undefined` if you only need to generate the `scriptPubKey` or `address` for a descriptor, or if all the public keys involved in the descriptor will sign the transaction. In the latter case, the satisfier will automatically choose the most optimal spending path (if more than one is available).
       */
      signersPubKeys?: Buffer[];
    }) {
      this.#network = network;
      this.#preimages = preimages;
      if (typeof expression !== 'string')
        throw new Error(`Error: invalid descriptor type`);

      const expandedResult = expand({
        expression,
        ...(index !== undefined ? { index } : {}),
        checksumRequired,
        network,
        allowMiniscriptInP2SH
      });
      if (expandedResult.isRanged && index === undefined)
        throw new Error(`Error: index was not provided for ranged descriptor`);
      if (!expandedResult.payment)
        throw new Error(
          `Error: could not extract a payment from ${expression}`
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
                  `Error: could not extract a pubkey from ${expression}`
                );
              return pubkey;
            }
          );
        } else {
          //We should only miss expansionMap in addr() expressions:
          if (!expandedResult.canonicalExpression.match(RE.reAddrAnchored)) {
            throw new Error(
              `Error: expansionMap not available for expression ${expression} that is not an address`
            );
          }
          this.#signersPubKeys = [this.getScriptPubKey()];
        }
      }
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
          signature: Buffer.alloc(64, 0)
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
    getPayment(): Payment {
      return this.#payment;
    }
    /**
     * Returns the Bitcoin Address
     */
    getAddress(): string {
      if (!this.#payment.address)
        throw new Error(`Error: could extract an address from the payment`);
      return this.#payment.address;
    }
    getScriptPubKey(): Buffer {
      if (!this.#payment.output)
        throw new Error(`Error: could extract output.script from the payment`);
      return this.#payment.output;
    }
    /**
     * Returns the compiled script satisfaction
     * @param {PartialSig[]} signatures An array of signatures using this format: `interface PartialSig { pubkey: Buffer; signature: Buffer; }`
     * @returns {Buffer}
     */
    getScriptSatisfaction(signatures: PartialSig[]): Buffer {
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
    getSequence(): number | undefined {
      return this.#getTimeConstraints()?.nSequence;
    }
    getLockTime(): number | undefined {
      return this.#getTimeConstraints()?.nLockTime;
    }
    getWitnessScript(): Buffer | undefined {
      return this.#witnessScript;
    }
    getRedeemScript(): Buffer | undefined {
      return this.#redeemScript;
    }
    getNetwork(): Network {
      return this.#network;
    }
    isSegwit(): boolean | undefined {
      return this.#isSegwit;
    }
    /**
     * Updates a Psbt where the descriptor describes an utxo.
     * The txHex (nonWitnessUtxo) and vout of the utxo must be passed.
     *
     * updatePsbt adds an input to the psbt and updates the tx locktime if needed.
     * It also adds a new input to the Psbt based on txHex
     * It returns the number of the input that is added.
     * psbt and vout are mandatory. Also pass txHex.
     *
     * The following is not recommended but, alternatively, ONLY for Segwit inputs,
     * you can pass txId and value, instead of txHex.
     * If you do so, it is your responsibility to make sure that `value` is
     * correct to avoid possible fee vulnerability attacks:
     * https://github.com/bitcoinjs/bitcoinjs-lib/issues/1625
     * Note that HW wallets require the full txHex also for Segwit anyways:
     * https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd
     *
     * In doubt, simply pass txHex (and you can skip passing txId and value) and
     * you shall be fine.
     */
    updatePsbt({
      psbt,
      txHex,
      txId,
      value,
      vout //vector output index
    }: {
      psbt: Psbt;
      txHex?: string;
      txId?: string;
      value?: number;
      vout: number;
    }): number {
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
      return updatePsbt({
        psbt,
        vout,
        ...(txHex !== undefined ? { txHex } : {}),
        ...(txId !== undefined ? { txId } : {}),
        ...(value !== undefined ? { value } : {}),
        sequence: this.getSequence(),
        locktime: this.getLockTime(),
        keysInfo: this.#expansionMap ? Object.values(this.#expansionMap) : [],
        scriptPubKey: this.getScriptPubKey(),
        isSegwit,
        witnessScript: this.getWitnessScript(),
        redeemScript: this.getRedeemScript()
      });
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
      let sequence = this.getSequence();
      if (sequence === undefined && locktime !== 0) sequence = 0xfffffffe;
      if (sequence === undefined && locktime === 0) sequence = 0xffffffff;
      if (
        Buffer.compare(scriptPubKey, this.getScriptPubKey()) !== 0 ||
        sequence !== inputSequence ||
        locktime !== psbt.locktime ||
        this.getWitnessScript() !== input.witnessScript ||
        this.getRedeemScript() !== input.redeemScript
      ) {
        throw new Error(
          `Error: cannot finalize psbt index ${index} since it does not correspond to this descriptor`
        );
      }
    }
    finalizePsbtInput({
      index,
      psbt,
      validate = true
    }: {
      index: number;
      psbt: Psbt;
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

      const signatures = psbt.data.inputs[index]?.partialSig;
      if (!signatures)
        throw new Error(`Error: cannot finalize without signatures`);
      this.#assertPsbtInput({ index, psbt });
      if (!this.#miniscript) {
        //Use standard finalizers
        psbt.finalizeInput(index);
      } else {
        const scriptSatisfaction = this.getScriptSatisfaction(signatures);
        psbt.finalizeInput(
          index,
          finalScriptsFuncFactory(scriptSatisfaction, this.#network)
        );
      }
    }
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

  return { Descriptor, parseKeyExpression, expand, ECPair, BIP32 };
}
/**
 * The {@link DescriptorsFactory | `DescriptorsFactory`} function internally creates and returns an instance of the {@link _Internal_.Descriptor | `Descriptor`} class.
 * This instance is specialized for the provided `TinySecp256k1Interface`.
 *
 * See the {@link _Internal_.Descriptor | documentation for the internal Descriptor class} for a complete list of available methods.
 */
type Descriptor = InstanceType<
  ReturnType<typeof DescriptorsFactory>['Descriptor']
>;
//type Expand = ReturnType<typeof DescriptorsFactory>['expand'];
//type ParseKeyExpression = ReturnType<
//  typeof DescriptorsFactory
//>['parseKeyExpression'];

export { Descriptor };
