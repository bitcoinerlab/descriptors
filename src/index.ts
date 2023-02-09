// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { compileMiniscript, satisfier } from '@bitcoinerlab/miniscript';
import {
  address,
  networks,
  payments,
  script as bscript,
  crypto,
  Network
} from 'bitcoinjs-lib';
const { p2sh, p2wpkh, p2pkh, p2pk, p2wsh } = payments;
import type { PartialSig } from 'bip174/src/lib/interfaces';

import type { TinySecp256k1Interface } from './tinysecp';

import { BIP32Factory, BIP32Interface } from 'bip32';
import { ECPairFactory } from 'ecpair';

import { DescriptorChecksum, CHECKSUM_CHARSET } from './checksum';

import { numberEncodeAsm } from './numberEncodeAsm';
export interface Preimage {
  digest: string; //Use same expressions as in miniscript. For example: "sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)" or "ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e)"
  //Accepted functions: sha256, hash256, ripemd160, hash160
  // 64-character HEX for sha256, hash160 or 30-character HEX for ripemd160 or hash160
  preimage: string; //Preimages are always 32 bytes (64 character in hex)
}

//See "Resource limitations" https://bitcoin.sipa.be/miniscript/
//https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-September/017306.html
const MAX_SCRIPT_ELEMENT_SIZE = 520;
const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
const MAX_OPS_PER_SCRIPT = 201;

//Regular expressions cheat sheet:
//https://www.keycdn.com/support/regex-cheat-sheet

//hardened characters
const reHardened = String.raw`(['hH])`;
//a level is a series of integers followed (optional) by a hardener char
const reLevel = String.raw`(\d+${reHardened}?)`;
//a path component is a level followed by a slash "/" char
const rePathComponent = String.raw`(${reLevel}\/)`;

//A path formed by a series of path components that can be hardened: /2'/23H/23
const reOriginPath = String.raw`(\/${rePathComponent}*${reLevel})`; //The "*" means: "match 0 or more of the previous"
//an origin is something like this: [d34db33f/44'/0'/0'] where the path is optional. The fingerPrint is 8 chars hex
const reOrigin = String.raw`(\[[0-9a-fA-F]{8}(${reOriginPath})?\])`;

const reChecksum = String.raw`(#[${CHECKSUM_CHARSET}]{8})`;

//Something like this: 0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2
//as explained here: github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#reference
const reCompressedPubKey = String.raw`((02|03)[0-9a-fA-F]{64})`;
const reUncompressedPubKey = String.raw`(04[0-9a-fA-F]{128})`;
const rePubKey = String.raw`(${reCompressedPubKey}|${reUncompressedPubKey})`;

//https://learnmeabitcoin.com/technical/wif
//5, K, L for mainnet, 5: uncompressed, {K, L}: compressed
//c, 9, testnet, c: compressed, 9: uncompressed
const reWIF = String.raw`([5KLc9][1-9A-HJ-NP-Za-km-z]{50,51})`;

//x for mainnet, t for testnet
const reXpub = String.raw`([xXtT]pub[1-9A-HJ-NP-Za-km-z]{79,108})`;
const reXprv = String.raw`([xXtT]prv[1-9A-HJ-NP-Za-km-z]{79,108})`;
//reRangeLevel is like reLevel but using a wildcard "*"
const reRangeLevel = String.raw`(\*(${reHardened})?)`;
//A path can be finished with stuff like this: /23 or /23h or /* or /*'
const rePath = String.raw`(\/(${rePathComponent})*(${reRangeLevel}|${reLevel}))`;
//rePath is optional (note the "zero"): Followed by zero or more /NUM or /NUM' path elements to indicate unhardened or hardened derivation steps between the fingerprint and the key or xpub/xprv root that follows
const reXpubKey = String.raw`(${reXpub})(${rePath})?`;
const reXprvKey = String.raw`(${reXprv})(${rePath})?`;

//actualKey is the keyExpression without optional origin
const reActualKey = String.raw`(${reXpubKey}|${reXprvKey}|${rePubKey}|${reWIF})`;
//reOrigin is optional: Optionally, key origin information, consisting of:
//Matches a key expression: wif, xpub, xprv or pubkey:
const reKeyExp = String.raw`(${reOrigin})?(${reActualKey})`;

const rePk = String.raw`pk\((.*?)\)`; //Matches anything. We assert later in the code that the pubkey is valid.
const reAddr = String.raw`addr\((.*?)\)`; //Matches anything. We assert later in the code that the address is valid.

const rePkh = String.raw`pkh\(${reKeyExp}\)`;
const reWpkh = String.raw`wpkh\(${reKeyExp}\)`;
const reShWpkh = String.raw`sh\(wpkh\(${reKeyExp}\)\)`;

const reMiniscript = String.raw`(.*?)`; //Matches anything. We assert later in the code that miniscripts are valid and sane.

//RegExp makers:
const makeReSh = (re: string) => String.raw`sh\(${re}\)`;
const makeReWsh = (re: string) => String.raw`wsh\(${re}\)`;
const makeReShWsh = (re: string) => makeReSh(makeReWsh(re));

const anchorStartAndEnd = (re: string) => String.raw`^${re}$`; //starts and finishes like re (not composable)

const composeChecksum = (re: string) => String.raw`${re}(${reChecksum})?`; //it's optional (note the "?")

const rePkAnchored = anchorStartAndEnd(composeChecksum(rePk));
const reAddrAnchored = anchorStartAndEnd(composeChecksum(reAddr));

const rePkhAnchored = anchorStartAndEnd(composeChecksum(rePkh));
const reWpkhAnchored = anchorStartAndEnd(composeChecksum(reWpkh));
const reShWpkhAnchored = anchorStartAndEnd(composeChecksum(reShWpkh));

const reShMiniscriptAnchored = anchorStartAndEnd(
  composeChecksum(makeReSh(reMiniscript))
);
const reShWshMiniscriptAnchored = anchorStartAndEnd(
  composeChecksum(makeReShWsh(reMiniscript))
);
const reWshMiniscriptAnchored = anchorStartAndEnd(
  composeChecksum(makeReWsh(reMiniscript))
);

/*
 * Returns a bare descriptor without checksum and particularized for a certain
 * index (if desc was a range descriptor)
 */
function isolate({
  expression,
  checksumRequired,
  index
}: {
  expression: string;
  checksumRequired: boolean;
  index: number;
}): string {
  const mChecksum = expression.match(String.raw`(${reChecksum})$`);
  if (mChecksum === null && checksumRequired === true)
    throw new Error(`Error: descriptor ${expression} has not checksum`);
  //isolatedExpression: a bare desc without checksum and particularized for a certain
  //index (if desc was a range descriptor)
  let isolatedExpression = expression;
  if (mChecksum !== null) {
    const checksum = mChecksum[0].substring(1); //remove the leading #
    isolatedExpression = expression.substring(
      0,
      expression.length - mChecksum[0].length
    );
    if (checksum !== DescriptorChecksum(isolatedExpression)) {
      throw new Error(`Error: invalid descriptor checksum for ${expression}`);
    }
  }
  let mWildcard = isolatedExpression.match(/\*/g);
  if (mWildcard && mWildcard.length > 0) {
    if (!Number.isInteger(index) || index < 0)
      throw new Error(`Error: invalid index ${index}`);
    //From  https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
    //To prevent a combinatorial explosion of the search space, if more than
    //one of the multi() key arguments is a BIP32 wildcard path ending in /* or
    //*', the multi() expression only matches multisig scripts with the ith
    //child key from each wildcard path in lockstep, rather than scripts with
    //any combination of child keys from each wildcard path.

    //We extend this reasoning for musig for all cases
    isolatedExpression = isolatedExpression.replaceAll('*', index.toString());
  }
  return isolatedExpression;
}

const derivePath = (node: BIP32Interface, path: string) => {
  if (typeof path !== 'string') {
    throw new Error(`Error: invalid derivation path ${path}`);
  }
  const parsedPath = path.replaceAll('H', "'").replaceAll('h', "'").slice(1);
  const splitPath = parsedPath.split('/');
  for (const element of splitPath) {
    const unhardened = element.endsWith("'") ? element.slice(0, -1) : element;
    if (
      !Number.isInteger(Number(unhardened)) ||
      Number(unhardened) >= 0x80000000
    )
      throw new Error(`Error: BIP 32 path element overflow`);
  }
  return node.derivePath(parsedPath);
};

/**
 * Builds the functions needed to operate with descriptors using an external elliptic curve (ecc) library.
 * @param {Object} ecc - an object containing elliptic curve operations, such as [tiny-secp256k1](https://github.com/bitcoinjs/tiny-secp256k1) or [@bitcoinerlab/secp256k1](https://github.com/bitcoinerlab/secp256k1).
 * @returns {Object} an object containing functions, `parse` and `checksum`.
 * @namespace
 */
export function DescriptorsFactory(ecc: TinySecp256k1Interface) {
  const bip32 = BIP32Factory(ecc);
  const ecpair = ECPairFactory(ecc);

  /*
   * Takes a key expression (xpub, xprv, pubkey or wif) and returns a pubkey in
   * binary format
   */
  function keyExpression2PubKey({
    keyExpression,
    network = networks.bitcoin,
    isSegwit = true
  }: {
    keyExpression: string;
    network?: Network;
    isSegwit?: boolean;
  }): Buffer {
    //Validate the keyExpression:
    const keyExpressions = keyExpression.match(reKeyExp);
    if (keyExpressions === null || keyExpressions[0] !== keyExpression) {
      throw new Error(
        `Error: expected a keyExpression but got ${keyExpression}`
      );
    }
    //Remove the origin (if it exists) and store result in actualKey
    const actualKey = keyExpression.replace(
      RegExp(String.raw`^(${reOrigin})?`),
      ''
    ); //starts with ^origin
    let mPubKey, mWIF, mXpubKey, mXprvKey;
    //match pubkey:
    if ((mPubKey = actualKey.match(anchorStartAndEnd(rePubKey))) !== null) {
      const pubkey = Buffer.from(mPubKey[0], 'hex');
      //Validate the pubkey (compressed or uncompressed)
      if (
        !ecc.isPoint(pubkey) ||
        (isSegwit && pubkey.length !== 33) || //Inside wpkh and wsh, only compressed public keys are permitted.
        !(pubkey.length === 33 || pubkey.length === 65)
      ) {
        throw new Error(`Error: invalid pubkey`);
      } else {
        return pubkey;
      }
      //match WIF:
    } else if ((mWIF = actualKey.match(anchorStartAndEnd(reWIF))) !== null) {
      //fromWIF will throw if the wif is not valid
      return ecpair.fromWIF(mWIF[0], network).publicKey;
      //match xpub:
    } else if (
      (mXpubKey = actualKey.match(anchorStartAndEnd(reXpubKey))) !== null
    ) {
      const xPubKey = mXpubKey[0];
      const xPub = xPubKey.match(reXpub)?.[0];
      if (!xPub) throw new Error(`Error: xpub could not be matched`);
      const mPath = xPubKey.match(rePath);
      if (mPath !== null) {
        const path = xPubKey.match(rePath)?.[0];
        if (!path) throw new Error(`Error: could not extract a path`);
        //fromBase58 and derivePath will throw if xPub or path are not valid
        return derivePath(bip32.fromBase58(xPub, network), path).publicKey;
      } else {
        return bip32.fromBase58(xPub, network).publicKey;
      }
      //match xprv:
    } else if (
      (mXprvKey = actualKey.match(anchorStartAndEnd(reXprvKey))) !== null
    ) {
      const xPrvKey = mXprvKey[0];
      const xPrv = xPrvKey.match(reXprv)?.[0];
      if (!xPrv) throw new Error(`Error: xprv could not be matched`);
      const mPath = xPrvKey.match(rePath);
      if (mPath !== null) {
        const path = xPrvKey.match(rePath)?.[0];
        if (!path) throw new Error(`Error: could not extract a path`);
        //fromBase58 and derivePath will throw if xPrv or path are not valid
        return derivePath(bip32.fromBase58(xPrv, network), path).publicKey;
      } else {
        return bip32.fromBase58(xPrv, network).publicKey;
      }
    } else {
      throw new Error(
        `Error: could not get pubkey for keyExpression ${keyExpression}`
      );
    }
  }

  function countNonPushOnlyOPs(script: Buffer): number {
    const decompile = bscript.decompile(script);
    if (!decompile) throw new Error(`Error: cound not decompile ${script}`);
    return decompile.filter(op => op > bscript.OPS['OP_16']!).length;
  }

  /**
   * Expand a miniscript to a generalized form using variables instead of key
   * expressions. Variables will be of this form: @0, @1, ...
   * This is done so that it can be compiled with compileMiniscript and
   * satisfied with satisfier.
   * Also compute pubKeys from descriptors to use them later.
   */
  function expandMiniscript({
    miniscript,
    isSegwit = true,
    network = networks.bitcoin
  }: {
    miniscript: string;
    isSegwit?: boolean;
    network?: Network;
  }): {
    expandedMiniscript: string;
    expansionMap: { [key: string]: string };
  } {
    const expansionMap: { [key: string]: string } = {};
    const expandedMiniscript = miniscript.replace(
      RegExp(reKeyExp, 'g'),
      (keyExpression: string) => {
        const key = '@' + Object.keys(expansionMap).length;
        expansionMap[key] = keyExpression2PubKey({
          keyExpression,
          network,
          isSegwit
        }).toString('hex');
        return key;
      }
    );
    const pubKeys = Object.values(expansionMap);
    if (new Set(pubKeys).size !== pubKeys.length) {
      throw new Error(
        `Error: miniscript ${miniscript} is not sane: contains duplicate public keys.`
      );
    }
    return { expandedMiniscript, expansionMap };
  }

  /**
   * Particularize an expanded ASM expression using the variables in
   * expansionMap.
   * This is the kind of the opposite to what expandMiniscript does.
   * Signatures and preimages are already subsituted by the satisfier calling
   * this function.
   */
  function substituteAsm({
    expandedAsm,
    expansionMap
  }: {
    expandedAsm: string;
    expansionMap: { [key: string]: string };
  }): string {
    //Replace back variables into the pubKeys previously computed.
    let asm = Object.keys(expansionMap).reduce((accAsm, key) => {
      const pubKey = expansionMap[key];
      if (!pubKey) {
        throw new Error(`Error: invalid expansionMap for ${key}`);
      }
      return accAsm
        .replaceAll(`<${key}>`, `<${expansionMap[key]}>`)
        .replaceAll(
          `<HASH160\(${key}\)>`,
          `<${crypto.hash160(Buffer.from(pubKey, 'hex')).toString('hex')}>`
        );
    }, expandedAsm);

    //Now clean it and prepare it so that fromASM can be called:
    asm = asm
      .trim()
      //Replace one or more consecutive whitespace characters (spaces, tabs,
      //or line breaks) with a single space.
      .replace(/\s+/g, ' ')
      //Now encode numbers to little endian hex. Note that numbers are not
      //enclosed in <>, since <> represents hex code already encoded.
      //The regex below will match one or more digits within a string,
      //except if the sequence is surrounded by "<" and ">"
      .replace(/(?<![<])\b\d+\b(?![>])/g, (num: string) =>
        numberEncodeAsm(Number(num))
      )
      //we don't have numbers anymore, now it's safe to remove < and > since we
      //know that every remaining is either an op_code or a hex encoded number
      .replace(/[<>]/g, '');

    return asm;
  }

  function miniscript2Script({
    miniscript,
    isSegwit = true,
    network = networks.bitcoin
  }: {
    miniscript: string;
    isSegwit?: boolean;
    network?: Network;
  }): Buffer {
    const { expandedMiniscript, expansionMap } = expandMiniscript({
      miniscript,
      isSegwit,
      network
    });
    const compiled = compileMiniscript(expandedMiniscript);
    if (compiled.issane !== true) {
      throw new Error(`Error: Miniscript ${expandedMiniscript} is not sane`);
    }
    return bscript.fromASM(
      substituteAsm({ expandedAsm: compiled.asm, expansionMap })
    );
  }

  /**
   * Assumptions:
   * The attacker does not have access to any of the private keys of public keys that participate in the Script.
   * The attacker only has access to hash preimages that honest users have access to as well.
   *
   * Pass constraints to search for the first solution with this nLockTime and nSequence.
   * Don't pass constraints (this is the default) if you want to get the smallest size solution altogether.
   *
   * It a solution is not found this function throws.
   */
  function satisfyMiniscript({
    miniscript,
    isSegwit = true,
    signatures = [],
    preimages = [],
    constraints,
    network = networks.bitcoin
  }: {
    miniscript: string;
    isSegwit?: boolean;
    signatures?: PartialSig[];
    preimages?: Preimage[];
    constraints?:
      | { nLockTime: number | undefined; nSequence: number | undefined }
      | undefined;
    network?: Network;
  }): {
    scriptSatisfaction: Buffer | undefined;
    nLockTime: number | undefined;
    nSequence: number | undefined;
  } {
    const { expandedMiniscript, expansionMap } = expandMiniscript({
      miniscript,
      isSegwit,
      network
    });

    //convert 'sha256(6c...33)' to: { ['<sha256_preimage(6c...33)>']: '10...5f'}
    let preimageMap: { [key: string]: string } = {};
    preimages.forEach(preimage => {
      preimageMap['<' + preimage.digest.replace('(', '_preimage(') + '>'] =
        '<' + preimage.preimage + '>';
    });

    //convert the pubkeys in signatures into [{['<sig(@0)>']: '30450221'}, ...]
    //get the keyExpressions: @0, @1 from the keys in expansionMap
    let expandedSignatureMap: { [key: string]: string } = {};
    signatures.forEach(signature => {
      const pubkey = signature.pubkey.toString('hex');
      const keyExpression = Object.keys(expansionMap).find(
        k => expansionMap[k] === pubkey
      );
      expandedSignatureMap['<sig(' + keyExpression + ')>'] =
        '<' + signature.signature.toString('hex') + '>';
    });
    const expandedKnownsMap = { ...preimageMap, ...expandedSignatureMap };
    const knowns = Object.keys(expandedKnownsMap);

    const { nonMalleableSats } = satisfier(expandedMiniscript, { knowns });

    if (!Array.isArray(nonMalleableSats) || !nonMalleableSats[0])
      throw new Error(`Error: unresolvable miniscript ${miniscript}`);

    let sat;
    if (!constraints) {
      sat = nonMalleableSats[0];
    } else {
      sat = nonMalleableSats.find(
        nonMalleableSat =>
          nonMalleableSat.nSequence === constraints.nSequence &&
          nonMalleableSat.nLockTime === constraints.nLockTime
      );
      if (sat === undefined) {
        throw new Error(
          `Error: unresolvable miniscript ${miniscript}. Could not find solutions for nSequence=${constraints.nSequence}, nLockTime=${constraints.nLockTime}. Signatures depend on sequence and locktime and would not match.`
        );
      }
    }

    //substitute signatures and preimages:
    let expandedAsm = sat.asm;
    //replace in expandedAsm all the <sig(@0)> and <sha256_preimage(6c...33)>
    //to <304...01> and <107...5f> ...
    for (const search in expandedKnownsMap) {
      const replace = expandedKnownsMap[search];
      if (!replace || replace === '<>')
        throw new Error(`Error: invalid expandedKnownsMap`);
      expandedAsm = expandedAsm.replaceAll(search, replace);
    }
    const scriptSatisfaction = bscript.fromASM(
      substituteAsm({ expandedAsm, expansionMap })
    );

    return {
      scriptSatisfaction,
      nLockTime: sat.nLockTime,
      nSequence: sat.nSequence
    };
  }

  class Descriptor {
    #payment;
    #signatures: PartialSig[] = [];
    #preimages: Preimage[] = [];
    #miniscript: string | undefined;
    #witnessScript: Buffer | undefined;
    #isSegwit: boolean = true;
    #network: Network;
    #nLockTime: number | undefined;
    #nSequence: number | undefined;
    /**
     * Parses a `descriptor`.
     *
     * Replaces the wildcard character * in range descriptors with `index`.
     *
     * Validates descriptor syntax and checksum.
     *
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
      signers = []
    }: {
      expression: string;
      index: number;
      checksumRequired?: boolean;
      allowMiniscriptInP2SH?: boolean;
      network?: Network;
      preimages?: Preimage[];
      signers?: string[];
    }) {
      this.#network = network;
      this.#preimages = preimages;
      if (typeof expression !== 'string')
        throw new Error(`Error: invalid descriptor type`);

      //Verify and remove checksum (if exists) and
      //particularize range descriptor for index (if desc is range descriptor)
      const isolatedExpression = isolate({
        expression,
        index,
        checksumRequired
      });

      const matchedAddress = isolatedExpression.match(reAddrAnchored)?.[1];
      const keyExpression = isolatedExpression.match(reKeyExp)?.[0];

      //addr(ADDR)
      if (matchedAddress) {
        let output;
        let payment;
        try {
          output = address.toOutputScript(matchedAddress, network);
        } catch (e) {
          throw new Error(`Error: invalid address ${matchedAddress}`);
        }
        try {
          payment = payments.p2pkh({ output, network });
        } catch (e) {}
        try {
          payment = payments.p2sh({ output, network });
        } catch (e) {}
        try {
          payment = payments.p2wpkh({ output, network });
        } catch (e) {}
        try {
          payment = payments.p2wsh({ output, network });
        } catch (e) {}
        try {
          payment = payments.p2tr({ output, network });
        } catch (e) {}
        if (!payment) {
          throw new Error(`Error: invalid address ${matchedAddress}`);
        }

        this.#payment = payment;
      }
      //pk(KEY)
      else if (isolatedExpression.match(rePkAnchored)) {
        if (isolatedExpression !== `pk(${keyExpression})`)
          throw new Error(`Error: invalid expression ${expression}`);
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        this.#isSegwit = false;
        const pubkey = keyExpression2PubKey({
          keyExpression,
          network,
          isSegwit: false
        });
        //Note there exists no address for p2pk, but we can still use the script
        this.#payment = p2pk({ pubkey, network });
      }
      //pkh(KEY) - legacy
      else if (isolatedExpression.match(rePkhAnchored)) {
        if (isolatedExpression !== `pkh(${keyExpression})`)
          throw new Error(`Error: invalid expression ${expression}`);
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        this.#isSegwit = false;
        const pubkey = keyExpression2PubKey({
          keyExpression,
          network,
          isSegwit: false
        });
        this.#payment = p2pkh({ pubkey, network });
      }
      //sh(wpkh(KEY)) - nested segwit
      else if (isolatedExpression.match(reShWpkhAnchored)) {
        if (isolatedExpression !== `sh(wpkh(${keyExpression}))`)
          throw new Error(`Error: invalid expression ${expression}`);
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        const pubkey = keyExpression2PubKey({
          keyExpression,
          network,
          isSegwit: true
        });
        this.#payment = p2sh({ redeem: p2wpkh({ pubkey, network }), network });
      }
      //wpkh(KEY) - native segwit
      else if (isolatedExpression.match(reWpkhAnchored)) {
        if (isolatedExpression !== `wpkh(${keyExpression})`)
          throw new Error(`Error: invalid expression ${expression}`);
        if (!keyExpression)
          throw new Error(`Error: keyExpression could not me extracted`);
        const pubkey = keyExpression2PubKey({
          keyExpression,
          network,
          isSegwit: true
        });
        this.#payment = p2wpkh({ pubkey, network });
      }
      //sh(wsh(miniscript))
      else if (isolatedExpression.match(reShWshMiniscriptAnchored)) {
        const miniscript = isolatedExpression.match(
          reShWshMiniscriptAnchored
        )?.[1]; //[1]-> whatever is found sh(wsh(->HERE<-))
        if (!miniscript)
          throw new Error(
            `Error: could not get miniscript in ${isolatedExpression}`
          );
        this.#miniscript = miniscript;
        const script = miniscript2Script({
          miniscript,
          network
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
      }
      //sh(miniscript)
      else if (isolatedExpression.match(reShMiniscriptAnchored)) {
        const miniscript = isolatedExpression.match(
          reShMiniscriptAnchored
        )?.[1]; //[1]-> whatever is found sh(->HERE<-)
        if (!miniscript)
          throw new Error(
            `Error: could not get miniscript in ${isolatedExpression}`
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
        this.#isSegwit = false;
        const script = miniscript2Script({
          miniscript,
          isSegwit: false,
          network
        });
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
      }
      //wsh(miniscript)
      else if (isolatedExpression.match(reWshMiniscriptAnchored)) {
        const miniscript = isolatedExpression.match(
          reWshMiniscriptAnchored
        )?.[1]; //[1]-> whatever is found wsh(->HERE<-)
        if (!miniscript)
          throw new Error(
            `Error: could not get miniscript in ${isolatedExpression}`
          );
        this.#miniscript = miniscript;
        const script = miniscript2Script({
          miniscript,
          network
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

      if (this.#miniscript) {
        //We create some fakeSignatures since we don't have them yet.
        //We only want to retrieve the nLockTime and nSequence of the satisfaction
        const fakeSignatures = signers.map(keyExpression => ({
          pubkey: keyExpression2PubKey({
            keyExpression,
            network,
            isSegwit: this.#isSegwit
          }),
          signature: Buffer.alloc(64, 0)
        }));
        const { nLockTime, nSequence } = satisfyMiniscript({
          miniscript: this.#miniscript,
          isSegwit: this.#isSegwit,
          signatures: fakeSignatures,
          preimages,
          network
        });
        this.#nLockTime = nLockTime;
        this.#nSequence = nSequence;
      }
    }
    getPayment() {
      return this.#payment;
    }
    getAddress() {
      if (!this.#payment.address)
        throw new Error(`Error: could extract an address from the payment`);
      return this.#payment.address;
    }
    getScriptPubKey() {
      if (!this.#payment.output)
        throw new Error(`Error: could extract output.script from the payment`);
      return this.#payment.output;
    }
    //TODO: This is wrong. getScriptWitness should only return if isSegwit is true.
    //If isSegwit is false then it's different
    getScriptWitness() {
      if (!this.#miniscript)
        throw new Error(
          `Error: this descriptor does not have a miniscript expression`
        );
      //Note that we pass the original nLockTime and nSequence that were
      //used to compute the signatures as constraings.
      //satisfyMiniscript will make sure
      //that the solution given, still meets the nLockTime and nSequence
      //conditions
      return satisfyMiniscript({
        miniscript: this.#miniscript,
        isSegwit: this.#isSegwit,
        signatures: this.#signatures,
        preimages: this.#preimages,
        constraints: {
          nLockTime: this.#nLockTime,
          nSequence: this.#nSequence
        },
        network: this.#network
      }).scriptSatisfaction;
    }
    getSequence() {
      return this.#nSequence;
    }
    getLockTime() {
      return this.#nLockTime;
    }
    getWitnessScript() {
      return this.#witnessScript;
    }
    getRedeemcript() {
      return this.#payment.redeem?.output;
    }
    addSignatures(signatures: PartialSig[]) {
      const pubkeys = this.#signatures.map(partialSig => partialSig.pubkey);
      const newPartialSigs = signatures.filter(
        partialSig => !pubkeys.includes(partialSig.pubkey)
      );
      this.#signatures = this.#signatures.concat(newPartialSigs);
    }
    /**
     * Computes the checksum of a descriptor.
     *
     * @Function
     * @param {string} descriptor - The descriptor.
     * @returns {string} - The checksum.
     */
    static checksum(expression: string) {
      return DescriptorChecksum(expression);
    }
    static keyExpression2PubKey({
      keyExpression,
      network = networks.bitcoin,
      isSegwit = true
    }: {
      keyExpression: string;
      network?: Network;
      isSegwit?: boolean;
    }): Buffer {
      return keyExpression2PubKey({ keyExpression, network, isSegwit });
    }
  }

  return Descriptor;
}
