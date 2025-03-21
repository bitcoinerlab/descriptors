// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { CHECKSUM_CHARSET } from './checksum';
//Regular expressions cheat sheet:
//https://www.keycdn.com/support/regex-cheat-sheet

//hardened characters
const reHardened = String.raw`(['hH])`;
//a level is a series of integers followed (optional) by a hardener char
const reLevel = String.raw`(\d+${reHardened}?)`;
//a path component is a level followed by a slash "/" char
const rePathComponent = String.raw`(${reLevel}\/)`;

//A path formed by a series of path components that can be hardened: /2'/23H/23
export const reOriginPath = String.raw`(\/${rePathComponent}*${reLevel})`; //The "*" means: "match 0 or more of the previous"
//an origin is something like this: [d34db33f/44'/0'/0'] where the path is optional. The fingerPrint is 8 chars hex
export const reMasterFingerprint = String.raw`[0-9a-fA-F]{8}`;
export const reOrigin = String.raw`(\[${reMasterFingerprint}(${reOriginPath})?\])`;

export const reChecksum = String.raw`(#[${CHECKSUM_CHARSET}]{8})`;

//Something like this: 0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2
//as explained here: github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#reference
const reCompressedPubKey = String.raw`((02|03)[0-9a-fA-F]{64})`;
const reUncompressedPubKey = String.raw`(04[0-9a-fA-F]{128})`;
const reXOnlyPubKey = String.raw`([0-9a-fA-F]{64})`;
export const reNonSegwitPubKey = String.raw`(${reCompressedPubKey}|${reUncompressedPubKey})`;
export const reSegwitPubKey = String.raw`(${reCompressedPubKey})`;
export const reTaprootPubKey = String.raw`(${reCompressedPubKey}|${reXOnlyPubKey})`;

//https://learnmeabitcoin.com/technical/wif
//5, K, L for mainnet, 5: uncompressed, {K, L}: compressed
//c, 9, testnet, c: compressed, 9: uncompressed
export const reWIF = String.raw`([5KLc9][1-9A-HJ-NP-Za-km-z]{50,51})`;

//x for mainnet, t for testnet
export const reXpub = String.raw`([xXtT]pub[1-9A-HJ-NP-Za-km-z]{79,108})`;
export const reXprv = String.raw`([xXtT]prv[1-9A-HJ-NP-Za-km-z]{79,108})`;
//reRangeLevel is like reLevel but using a wildcard "*"
const reRangeLevel = String.raw`(\*(${reHardened})?)`;
//A path can be finished with stuff like this: /23 or /23h or /* or /*'
export const rePath = String.raw`(\/(${rePathComponent})*(${reRangeLevel}|${reLevel}))`;
//rePath is optional (note the "zero"): Followed by zero or more /NUM or /NUM' path elements to indicate unhardened or hardened derivation steps between the fingerprint and the key or xpub/xprv root that follows
export const reXpubKey = String.raw`(${reXpub})(${rePath})?`;
export const reXprvKey = String.raw`(${reXprv})(${rePath})?`;

//actualKey is the keyExpression without optional origin
const reNonSegwitActualKey = String.raw`(${reXpubKey}|${reXprvKey}|${reNonSegwitPubKey}|${reWIF})`;
const reSegwitActualKey = String.raw`(${reXpubKey}|${reXprvKey}|${reSegwitPubKey}|${reWIF})`;
const reTaprootActualKey = String.raw`(${reXpubKey}|${reXprvKey}|${reTaprootPubKey}|${reWIF})`;
//reOrigin is optional: Optionally, key origin information, consisting of:
//Matches a key expression: wif, xpub, xprv or pubkey:
export const reNonSegwitKeyExp = String.raw`(${reOrigin})?(${reNonSegwitActualKey})`;
export const reSegwitKeyExp = String.raw`(${reOrigin})?(${reSegwitActualKey})`;
export const reTaprootKeyExp = String.raw`(${reOrigin})?(${reTaprootActualKey})`;

const rePk = String.raw`pk\((.*?)\)`; //Matches anything. We assert later in the code that the pubkey is valid.
const reAddr = String.raw`addr\((.*?)\)`; //Matches anything. We assert later in the code that the address is valid.

const rePkh = String.raw`pkh\(${reNonSegwitKeyExp}\)`;
const reWpkh = String.raw`wpkh\(${reSegwitKeyExp}\)`;
const reShWpkh = String.raw`sh\(wpkh\(${reSegwitKeyExp}\)\)`;
const reTrSingleKey = String.raw`tr\(${reTaprootKeyExp}\)`; // TODO: tr(KEY,TREE) not yet supported. TrSingleKey used for tr(KEY)

const reMiniscript = String.raw`(.*?)`; //Matches anything. We assert later in the code that miniscripts are valid and sane.

//RegExp makers:
const makeReSh = (re: string) => String.raw`sh\(${re}\)`;
const makeReWsh = (re: string) => String.raw`wsh\(${re}\)`;
const makeReShWsh = (re: string) => makeReSh(makeReWsh(re));

export const anchorStartAndEnd = (re: string) => String.raw`^${re}$`; //starts and finishes like re (not composable)

const composeChecksum = (re: string) => String.raw`${re}(${reChecksum})?`; //it's optional (note the "?")

export const rePkAnchored = anchorStartAndEnd(composeChecksum(rePk));
export const reAddrAnchored = anchorStartAndEnd(composeChecksum(reAddr));

export const rePkhAnchored = anchorStartAndEnd(composeChecksum(rePkh));
export const reWpkhAnchored = anchorStartAndEnd(composeChecksum(reWpkh));
export const reShWpkhAnchored = anchorStartAndEnd(composeChecksum(reShWpkh));
export const reTrSingleKeyAnchored = anchorStartAndEnd(
  composeChecksum(reTrSingleKey)
);

export const reShMiniscriptAnchored = anchorStartAndEnd(
  composeChecksum(makeReSh(reMiniscript))
);
export const reShWshMiniscriptAnchored = anchorStartAndEnd(
  composeChecksum(makeReShWsh(reMiniscript))
);
export const reWshMiniscriptAnchored = anchorStartAndEnd(
  composeChecksum(makeReWsh(reMiniscript))
);
