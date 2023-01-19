// Copyright (c) 2023 Jose-Luis Landabaso
// Distributed under the MIT software license

/** @module descriptors */

import { compileMiniscript } from '@bitcoinerlab/miniscript';
import { address, networks, payments, script } from 'bitcoinjs-lib';
const { p2sh, p2wpkh, p2pkh, p2pk, p2wsh } = payments;

import BIP32Factory from 'bip32';
import ECPairFactory from 'ecpair';

import { DescriptorChecksum, CHECKSUM_CHARSET } from './checksum';

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
const makeReSh = re => String.raw`sh\(${re}\)`;
const makeReWsh = re => String.raw`wsh\(${re}\)`;
const makeReShWsh = re => makeReSh(makeReWsh(re));

const anchorStartAndEnd = re => String.raw`^${re}$`; //starts and finishes like re (not composable)

const composeChecksum = re => String.raw`${re}(${reChecksum})?`; //it's optional (note the "?")

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

/** @namespace */
export function DescriptorsFactory(ecc) {
  const bip32 = BIP32Factory(ecc);
  const ecpair = ECPairFactory(ecc);

  /* Takes a key expression (xpub, xprv, pubkey or wif) and returns a pubkey in
   * binary format
   */
  function keyExpression2PubKey({
    keyExp,
    network = networks.bitcoin,
    isSegwit = true
  }) {
    //Validate the keyExp:
    const keyExps = keyExp.match(reKeyExp);
    if (keyExps === null || keyExps[0] !== keyExp) {
      throw new Error(`Error: expected a keyExp but got ${keyExp}`);
    }
    //Remove the origin (if it exists) and store result in actualKey
    const actualKey = keyExp.replace(RegExp(String.raw`^(${reOrigin})?`), ''); //starts with ^origin
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
      const xPub = xPubKey.match(reXpub)[0];
      const path = xPubKey.match(rePath)[0];
      //fromBase58 and derivePath will throw if xPub or path are not valid
      return bip32
        .fromBase58(xPub, network)
        .derivePath(path.replaceAll('H', "'").replaceAll('h', "'").slice(1))
        .publicKey;
      //match xrv:
    } else if (
      (mXprvKey = actualKey.match(anchorStartAndEnd(reXprvKey))) !== null
    ) {
      const xPrvKey = mXprvKey[0];
      const xPrv = xPrvKey.match(reXprv)[0];
      const path = xPrvKey.match(rePath)[0];
      //fromBase58 and derivePath will throw if xPrv or path are not valid
      return bip32
        .fromBase58(xPrv, network)
        .derivePath(path.replaceAll('H', "'").replaceAll('h', "'").slice(1))
        .publicKey;
    } else {
      throw new Error(`Error: could not get pubkey for keyExp ${keyExp}`);
    }
  }

  /*
   * Returns a bare descriptor without checksum and particularized for a certain
   * index (if desc was a rage descriptor)
   */
  function isolate({ desc, checksumRequired, index }) {
    const mChecksum = desc.match(String.raw`(${reChecksum})$`);
    if (mChecksum === null && checksumRequired === true)
      throw new Error(`Error: descriptor ${desc} has not checksum`);
    //isolatedDesc: a bare desc without checksum and particularized for a certain
    //index (if desc was a rage descriptor)
    let isolatedDesc = desc;
    if (mChecksum !== null) {
      const checksum = mChecksum[0].substring(1); //remove the leading #
      isolatedDesc = desc.substring(0, desc.length - mChecksum[0].length);
      if (checksum !== DescriptorChecksum(isolatedDesc)) {
        throw new Error(`Error: invalid descriptor checksum for ${desc}`);
      }
    }
    let mWildcard = isolatedDesc.match(/\*/g);
    if (mWildcard && mWildcard.length > 1) {
      throw new Error(
        `Error: cannot extract an address when using multiple ranges`
      );
    }
    if (mWildcard && mWildcard.length === 1) {
      if (!Number.isInteger(index) || index < 0)
        throw new Error(`Error: invalid index ${index}`);
      isolatedDesc = isolatedDesc.replace('*', index);
    }
    return isolatedDesc;
  }

  function miniscript2Script({
    miniscript,
    isSegwit = true,
    network = networks.bitcoin
  }) {
    //Repalace miniscript's descriptors to variables: key_0, key_1, ... so that
    //miniscript can be compiled with compileMiniscript
    //Also compute pubKeys from descriptors to use them later.
    const keyMap = {};
    const bareM = miniscript.replace(RegExp(reKeyExp, 'g'), keyExp => {
      const key = 'key_' + Object.keys(keyMap).length;
      keyMap[key] = keyExpression2PubKey({
        keyExp,
        network,
        isSegwit
      }).toString('hex');
      return key;
    });
    const compiled = compileMiniscript(bareM);
    if (compiled.issane !== true) {
      throw new Error(`Error: Miniscript ${bareM} is not sane`);
    }
    //Replace back variables into the pubKeys previously computed.
    const asm = compiled.asm.replace(
      new RegExp(Object.keys(keyMap).join('|'), 'g'),
      key => keyMap[key]
    );
    //Create binary code from the asm above. Prepare asm:
    //Replace one or more consecutive whitespace characters (spaces, tabs, or line
    //breaks) with a single space.
    //Convert <hexcode> into hexcode (without <, >) as expected in fromASM.
    return script.fromASM(asm.trim().replace(/\s+/g, ' ').replace(/[<>]/g, ''));
  }

  /**
   * Parses a `descriptor` and returns a [`Payment`](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/index.d.ts) object from bitcoinjs-lib, including address, output script, and other information.
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
   * @returns {Payment} A bitcoinjs `Payment` object containing the parsed descriptor's information, including a string with the `addresss`, and a `Buffer` with the `output` script:
   * ```typescript
   * interface Payment {
   *     name?: string;
   *     network?: Network;
   *     output?: Buffer;
   *     data?: Buffer[];
   *     m?: number;
   *     n?: number;
   *     pubkeys?: Buffer[];
   *     input?: Buffer;
   *     signatures?: Buffer[];
   *     internalPubkey?: Buffer;
   *     pubkey?: Buffer;
   *     signature?: Buffer;
   *     address?: string;
   *     hash?: Buffer;
   *     redeem?: Payment;
   *     redeemVersion?: number;
   *     scriptTree?: Taptree;
   *     witness?: Buffer[];
   * }
   * ```
   *
   * @see {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/index.d.ts}
   * @throws {Error} - when descriptor is invalid
   */
  function parse({
    desc,
    index,
    checksumRequired = true,
    network = networks.bitcoin
  }) {
    //verify and remove checksum (if exists) and
    //particularize rante descriptor for index (if desc is range descriptor)
    const isolatedDesc = isolate({ desc, index, checksumRequired });

    //addr(ADDR)
    if (isolatedDesc.match(reAddrAnchored)) {
      const matchedAddress = isolatedDesc.match(reAddrAnchored)[1]; //[1] -> whatever is inside addr(->HERE<-)
      try {
        address.toOutputScript(matchedAddress, network);
      } catch (e) {
        throw new Error(`Error: invalid address ${matchedAddress}`);
      }
      return { address: matchedAddress };
    }
    //pk(KEY)
    else if (isolatedDesc.match(rePkAnchored)) {
      const keyExp = isolatedDesc.match(reKeyExp)[0];
      if (isolatedDesc !== `pk(${keyExp})`)
        throw new Error(`Error: invalid desc ${desc}`);
      const pubkey = keyExpression2PubKey({ keyExp, network, isSegwit: false });
      //Note, this is the script, not the address
      return p2pk({ pubkey, network });
    }
    //pkh(KEY) - legacy
    else if (isolatedDesc.match(rePkhAnchored)) {
      const keyExp = isolatedDesc.match(reKeyExp)[0];
      if (isolatedDesc !== `pkh(${keyExp})`)
        throw new Error(`Error: invalid desc ${desc}`);
      const pubkey = keyExpression2PubKey({ keyExp, network, isSegwit: false });
      return p2pkh({ pubkey, network });
    }
    //sh(wpkh(KEY)) - nested segwit
    else if (isolatedDesc.match(reShWpkhAnchored)) {
      const keyExp = isolatedDesc.match(reKeyExp)[0];
      if (isolatedDesc !== `sh(wpkh(${keyExp}))`)
        throw new Error(`Error: invalid desc ${desc}`);
      const pubkey = keyExpression2PubKey({ keyExp, network });
      return p2sh({ redeem: p2wpkh({ pubkey, network }), network });
    }
    //wpkh(KEY) - native segwit
    else if (isolatedDesc.match(reWpkhAnchored)) {
      const keyExp = isolatedDesc.match(reKeyExp)[0];
      if (isolatedDesc !== `wpkh(${keyExp})`)
        throw new Error(`Error: invalid desc ${desc}`);
      const pubkey = keyExpression2PubKey({ keyExp, network });
      return p2wpkh({ pubkey, network });
    }
    //sh(wsh(miniscript))
    else if (isolatedDesc.match(reShWshMiniscriptAnchored)) {
      const miniscript = isolatedDesc.match(reShWshMiniscriptAnchored)[1]; //[1]-> whatever is found sh(wsh(->HERE<-))
      const script = miniscript2Script({ miniscript, network });
      return p2sh({
        redeem: p2wsh({ redeem: { output: script }, network }),
        network
      });
    }
    //sh(miniscript)
    else if (isolatedDesc.match(reShMiniscriptAnchored)) {
      const miniscript = isolatedDesc.match(reWshMiniscriptAnchored)[1]; //[1]-> whatever is found wsh(->HERE<-)
      const script = miniscript2Script({
        miniscript,
        isSegwit: false,
        network
      });
      return p2sh({ redeem: { output: script }, network });
    }
    //wsh(miniscript)
    else if (isolatedDesc.match(reWshMiniscriptAnchored)) {
      const miniscript = isolatedDesc.match(reShMiniscriptAnchored)[1]; //[1]-> whatever is found sh(->HERE<-)
      const script = miniscript2Script({ miniscript, network });
      return p2wsh({ redeem: { output: script }, network });
    } else {
      throw new Error(`Error: Could not parse descriptor ${desc}`);
    }
  }

  /**
   * Computes the checksum of a descriptor.
   *
   * @Function
   * @param {string} descriptor - The descriptor.
   * @returns {string} - The checksum.
   */
  const checksum = DescriptorChecksum;

  return { parse, checksum };
}
