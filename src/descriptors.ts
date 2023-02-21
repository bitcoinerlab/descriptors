// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

//TODO: ledger integration test: Use 3 standard inputs + miniscript - Test using value instead of txHex. Does it work? I believe not.
//TODO: Ledger guide showing how to receive and spend with 4 inputs: 3 standard + 1 miniscript
//TODO: In tests documentation explain the tools folder -> generate bitcoinCore fixtures
//TODO: export a finalizePsbt function
//TODO: wpkhBIP32 -> wpkhExpressionBIP32

import {
  address,
  networks,
  payments,
  script as bscript,
  Network,
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
  ParseKeyExpression,
  DescriptorInterfaceConstructor,
  DescriptorInterface,
  DescriptorInfo
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
  return decompile.filter(op => op > bscript.OPS['OP_16']!).length;
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
  let mWildcard = evaluatedExpression.match(/\*/g);
  if (mWildcard && mWildcard.length > 0) {
    if (index === undefined)
      throw new Error(`Error: index was not provided for ranged descriptor`);
    if (!Number.isInteger(index) || index < 0)
      throw new Error(`Error: invalid index ${index}`);
    //From  https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    //To prevent a combinatorial explosion of the search space, if more than
    //one of the multi() key arguments is a BIP32 wildcard path ending in /* or
    //*', the multi() expression only matches multisig scripts with the ith
    //child key from each wildcard path in lockstep, rather than scripts with
    //any combination of child keys from each wildcard path.

    //We extend this reasoning for musig for all cases
    evaluatedExpression = evaluatedExpression.replaceAll('*', index.toString());
  }
  return evaluatedExpression;
}

/**
 * Builds the functions needed to operate with descriptors using an external elliptic curve (ecc) library.
 * @param {Object} ecc - an object containing elliptic curve operations, such as [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1) or [@bitcoinerlab/secp256k1](https://github.com/bitcoinerlab/secp256k1).
 * @returns {Object} an object containing functions, `parse` and `checksum`.
 * @namespace
 */
export function DescriptorsFactory(ecc: TinySecp256k1Interface): {
  Descriptor: DescriptorInterfaceConstructor;
  ECPair: ECPairAPI;
  parseKeyExpression: ParseKeyExpression;
  BIP32: BIP32API;
} {
  const BIP32: BIP32API = BIP32Factory(ecc);
  const ECPair: ECPairAPI = ECPairFactory(ecc);

  /*
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

  class Descriptor implements DescriptorInterface {
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
     * @param {Object} params
     * @param {number} params.index - The descriptor's index in the case of a range descriptor (must be an interger >=0).
     * @param {string} params.descriptor - The descriptor.
     * @param {boolean} [params.checksumRequired=false] - A flag indicating whether the descriptor is required to include a checksum.
     * @param {object} [params.network=networks.bitcoin] One of bitcoinjs-lib [`networks`](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/networks.js) (or another one following the same interface).
     *
     * @see {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/index.d.ts}
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
    }: DescriptorInfo) {
      this.#network = network;
      this.#preimages = preimages;
      if (typeof expression !== 'string')
        throw new Error(`Error: invalid descriptor type`);

      //Verify and remove checksum (if exists) and
      //particularize range descriptor for index (if desc is range descriptor)
      const evaluatedExpression = evaluate({
        expression,
        ...(index !== undefined ? { index } : {}),
        checksumRequired
      });

      //addr(ADDR)
      if (evaluatedExpression.match(RE.reAddrAnchored)) {
        const matchedAddress = evaluatedExpression.match(
          RE.reAddrAnchored
        )?.[1]; //[1]-> whatever is found addr(->HERE<-)
        if (!matchedAddress)
          throw new Error(
            `Error: could not get an address in ${evaluatedExpression}`
          );
        let output;
        let payment;
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
        this.#payment = payment;
      }
      //pk(KEY)
      else if (evaluatedExpression.match(RE.rePkAnchored)) {
        this.#isSegwit = false;
        const keyExpression = evaluatedExpression.match(RE.reKeyExp)?.[0];
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        if (evaluatedExpression !== `pk(${keyExpression})`)
          throw new Error(`Error: invalid expression ${expression}`);
        this.#expandedExpression = 'pk(@0)';
        this.#expansionMap = {
          '@0': parseKeyExpression({
            keyExpression,
            network,
            isSegwit: this.#isSegwit
          })
        };
        const pubkey = this.#expansionMap['@0']!.pubkey;
        //Note there exists no address for p2pk, but we can still use the script
        this.#payment = p2pk({ pubkey, network });
      }
      //pkh(KEY) - legacy
      else if (evaluatedExpression.match(RE.rePkhAnchored)) {
        this.#isSegwit = false;
        const keyExpression = evaluatedExpression.match(RE.reKeyExp)?.[0];
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        if (evaluatedExpression !== `pkh(${keyExpression})`)
          throw new Error(`Error: invalid expression ${expression}`);
        this.#expandedExpression = 'pkh(@0)';
        this.#expansionMap = {
          '@0': parseKeyExpression({
            keyExpression,
            network,
            isSegwit: this.#isSegwit
          })
        };
        const pubkey = this.#expansionMap['@0']!.pubkey;
        this.#payment = p2pkh({ pubkey, network });
      }
      //sh(wpkh(KEY)) - nested segwit
      else if (evaluatedExpression.match(RE.reShWpkhAnchored)) {
        this.#isSegwit = true;
        const keyExpression = evaluatedExpression.match(RE.reKeyExp)?.[0];
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        if (evaluatedExpression !== `sh(wpkh(${keyExpression}))`)
          throw new Error(`Error: invalid expression ${expression}`);
        this.#expandedExpression = 'sh(wpkh(@0))';
        this.#expansionMap = {
          '@0': parseKeyExpression({
            keyExpression,
            network,
            isSegwit: this.#isSegwit
          })
        };
        const pubkey = this.#expansionMap['@0']!.pubkey;
        this.#payment = p2sh({ redeem: p2wpkh({ pubkey, network }), network });
        const redeemScript = this.#payment.redeem?.output;
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${expression}`
          );
        this.#redeemScript = redeemScript;
      }
      //wpkh(KEY) - native segwit
      else if (evaluatedExpression.match(RE.reWpkhAnchored)) {
        this.#isSegwit = true;
        const keyExpression = evaluatedExpression.match(RE.reKeyExp)?.[0];
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        if (evaluatedExpression !== `wpkh(${keyExpression})`)
          throw new Error(`Error: invalid expression ${expression}`);
        this.#expandedExpression = 'wpkh(@0)';
        this.#expansionMap = {
          '@0': parseKeyExpression({
            keyExpression,
            network,
            isSegwit: this.#isSegwit
          })
        };
        const pubkey = this.#expansionMap['@0']!.pubkey;
        this.#payment = p2wpkh({ pubkey, network });
      }
      //sh(wsh(miniscript))
      else if (evaluatedExpression.match(RE.reShWshMiniscriptAnchored)) {
        this.#isSegwit = true;
        const miniscript = evaluatedExpression.match(
          RE.reShWshMiniscriptAnchored
        )?.[1]; //[1]-> whatever is found sh(wsh(->HERE<-))
        if (!miniscript)
          throw new Error(
            `Error: could not get miniscript in ${evaluatedExpression}`
          );
        this.#miniscript = miniscript;
        ({
          expandedMiniscript: this.#expandedMiniscript,
          expansionMap: this.#expansionMap
        } = expandMiniscript({
          miniscript,
          isSegwit: this.#isSegwit,
          network
        }));
        this.#expandedExpression = `sh(wsh(${this.#expandedMiniscript}))`;

        const script = miniscript2Script({
          expandedMiniscript: this.#expandedMiniscript,
          expansionMap: this.#expansionMap
        });
        this.#witnessScript = script;
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
        this.#payment = p2sh({
          redeem: p2wsh({ redeem: { output: script, network }, network }),
          network
        });
        const redeemScript = this.#payment.redeem?.output;
        if (!redeemScript)
          throw new Error(
            `Error: could not calculate redeemScript for ${expression}`
          );
        this.#redeemScript = redeemScript;
      }
      //sh(miniscript)
      else if (evaluatedExpression.match(RE.reShMiniscriptAnchored)) {
        //isSegwit false because we know it's a P2SH of a miniscript and not a
        //P2SH that embeds a witness payment.
        this.#isSegwit = false;
        const miniscript = evaluatedExpression.match(
          RE.reShMiniscriptAnchored
        )?.[1]; //[1]-> whatever is found sh(->HERE<-)
        if (!miniscript)
          throw new Error(
            `Error: could not get miniscript in ${evaluatedExpression}`
          );
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
        this.#miniscript = miniscript;
        ({
          expandedMiniscript: this.#expandedMiniscript,
          expansionMap: this.#expansionMap
        } = expandMiniscript({
          miniscript,
          isSegwit: this.#isSegwit,
          network
        }));
        this.#expandedExpression = `sh(${this.#expandedMiniscript})`;

        const script = miniscript2Script({
          expandedMiniscript: this.#expandedMiniscript,
          expansionMap: this.#expansionMap
        });
        this.#redeemScript = script;
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
        this.#payment = p2sh({ redeem: { output: script, network }, network });
        if (Buffer.compare(script, this.getRedeemScript()!) !== 0)
          throw new Error(
            `Error: redeemScript was not correctly set to the payment in expression ${expression}`
          );
      }
      //wsh(miniscript)
      else if (evaluatedExpression.match(RE.reWshMiniscriptAnchored)) {
        this.#isSegwit = true;
        const miniscript = evaluatedExpression.match(
          RE.reWshMiniscriptAnchored
        )?.[1]; //[1]-> whatever is found wsh(->HERE<-)
        if (!miniscript)
          throw new Error(
            `Error: could not get miniscript in ${evaluatedExpression}`
          );
        this.#miniscript = miniscript;
        ({
          expandedMiniscript: this.#expandedMiniscript,
          expansionMap: this.#expansionMap
        } = expandMiniscript({
          miniscript,
          isSegwit: this.#isSegwit,
          network
        }));
        this.#expandedExpression = `wsh(${this.#expandedMiniscript})`;

        const script = miniscript2Script({
          expandedMiniscript: this.#expandedMiniscript,
          expansionMap: this.#expansionMap
        });
        this.#witnessScript = script;
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
        this.#payment = p2wsh({ redeem: { output: script, network }, network });
      } else {
        throw new Error(`Error: Could not parse descriptor ${expression}`);
      }
      if (signersPubKeys) {
        this.#signersPubKeys = signersPubKeys;
      } else {
        if (this.#expansionMap) {
          this.#signersPubKeys = Object.values(this.#expansionMap).map(
            keyInfo => keyInfo.pubkey
          );
        } else {
          //We should only miss expansionMap in addr() expressions:
          if (!evaluatedExpression.match(RE.reAddrAnchored)) {
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
    finalizePsbtInput({ index, psbt }: { index: number; psbt: Psbt }): void {
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
    expand(): {
      expandedExpression?: string;
      miniscript?: string;
      expandedMiniscript?: string;
      expansionMap?: ExpansionMap;
    } {
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

  return { Descriptor, parseKeyExpression, ECPair, BIP32 };
}
