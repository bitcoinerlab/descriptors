//TODO: tests for uncompressed pubKey
//TODO: tests for WIF - /^[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}$/
//TODO: check wifs!
//https://github.com/bitcoinjs/wif
//TODO: tests for xprv
//TODO: also add ADDR expressions: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
//Verify the address:
//export function checkAddress(address, network) {
//  checkNetwork(network);
//  try {
//    bjsAddress.toOutputScript(address, network);
//    return true;
//  } catch (e) {
//    throw new Error('Invalid address');
//  }
//}
//TODO: check that we Do not suport yzpub...
//TODO: use fromBase58 to validate xpub, xpriv
//TODO: support checksums: Descriptors can optionally be suffixed with a checksum to protect against typos or copy-paste errors.
//TODO: Document that it supports all SCRIPT expressions, including also all possible miniscript, but it does not support raw(), combo(), sortedmulti(), tr(), multi_ (taproot), sortedmulti_a (taproot), rawtr (taproot)
//TODO: support wif, xpriv
//TODO: check pubkeys validity: https://github.com/bitcoinjs/bitcoinjs-lib/pull/1573/commits/25b5806cf146ef5d5f5770c60f102a7b37bcf660
//if (!ecc.isPoint(a.witness[1]))
//TODO: wpkh and wsh allow only compressed pubkeys
//see: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
import { compileMiniscript } from '@bitcoinerlab/miniscript';
import { networks, payments, script } from 'bitcoinjs-lib';
const { p2sh, p2wpkh, p2pkh, p2wsh } = payments;

import * as ecc from '@bitcoinerlab/secp256k1';
import BIP32Factory from 'bip32';
const bip32 = BIP32Factory(ecc);

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

const reActualKey = String.raw`(${reXpubKey}|${reXprvKey}|${rePubKey}|${reWIF})`;
//reOrigin is optional: Optionally, key origin information, consisting of:
const reDescKey = String.raw`(${reOrigin})?(${reActualKey})`;

const rePkh = String.raw`pkh\(${reDescKey}\)`;
const reWpkh = String.raw`wpkh\(${reDescKey}\)`;
const reShWpkh = String.raw`sh\(wpkh\(${reDescKey}\)\)`;

const reMiniscript = String.raw`(.*?)`; //matches anything. We check in the code that miniscripts are valid and sane.

//RegExp makers:
const makeReSh = re => String.raw`sh\(${re}\)`;
const makeReWsh = re => String.raw`wsh\(${re}\)`;
const makeReShWsh = re => makeReSh(makeReWsh(re));

const makeReOut = re => String.raw`^${re}$`; //starts and finishes like re (not composable)

const rePkhOut = makeReOut(rePkh);
const reWpkhOut = makeReOut(reWpkh);
const reShWpkhOut = makeReOut(reShWpkh);

const reShMiniscriptOut = makeReOut(makeReSh(reMiniscript));
const reShWshMiniscriptOut = makeReOut(makeReShWsh(reMiniscript));
const reWshMiniscriptOut = makeReOut(makeReWsh(reMiniscript));

/** Takes a descriptor and returns a pubKey in binary format*/
function keyExpression2PubKey({ desc, network = networks.bitcoin }) {
  //TODO: assert that there is only one desc
  const descKey = desc.match(reDescKey)[0];
  const mPubKey = descKey.match(rePubKey);
  if (mPubKey) {
    return Buffer.from(mPubKey[0], 'hex');
  } else {
    const xPubKey = descKey.match(reXpubKey)[0];
    const xPub = xPubKey.match(reXpub)[0];
    const path = xPubKey.match(rePath)[0];
    return bip32
      .fromBase58(xPub, network)
      .derivePath(path.replaceAll('H', "'").replaceAll('h', "'").slice(1))
      .publicKey;
  }
}

function desc2Script({ desc, network }) {
  let miniscript;
  //start with longer match possible "sh(wsh("
  if (desc.match(reShWshMiniscriptOut)) {
    miniscript = desc.match(reShWshMiniscriptOut)[1]; //[1]-> whatever is found sh(wsh(->HERE<-))
  } else if (desc.match(reWshMiniscriptOut)) {
    miniscript = desc.match(reWshMiniscriptOut)[1]; //[1]-> whatever is found wsh(->HERE<-)
  } else if (desc.match(reShMiniscriptOut)) {
    miniscript = desc.match(reShMiniscriptOut)[1]; //[1]-> whatever is found sh(->HERE<-)
  } else {
    throw new Error(`Error getting script from descriptor ${desc}.`);
  }
  //
  //Repalace miniscript's descriptors to variables: key_0, key_1, ... so that
  //miniscript can be compiled with compileMiniscript
  //Also compute pubKeys from descriptors to use them later.
  const keyMap = {};
  const bareM = miniscript.replace(RegExp(reDescKey, 'g'), desc => {
    const key = 'key_' + Object.keys(keyMap).length;
    keyMap[key] = keyExpression2PubKey({ desc, network }).toString('hex');
    return key;
  });
  const compiled = compileMiniscript(bareM);
  if (compiled.issane !== true) {
    throw new Error(`Miniscript ${bareM} is not sane.`);
  }
  //Replace back variables into the pubKeys previously computed.
  const asm = compiled.asm.replace(
    new RegExp(Object.keys(keyMap).join('|'), 'g'),
    matched => keyMap[matched]
  );
  //Create binary code from the asm above. Prepare asm:
  //Replace one or more consecutive whitespace characters (spaces, tabs, or line
  //breaks) with a single space.
  //Convert <hexcode> into hexcode (without <, >) as expected in fromASM.
  return script.fromASM(asm.trim().replace(/\s+/g, ' ').replace(/[<>]/g, ''));
}

/** Returns the address of an output descriptor*/
export function address({ desc, network = networks.bitcoin }) {
  //TODO: Assertions, make sure it is not a range desc
  //Check the network
  //Assert the pubkeys

  //legacy
  if (desc.match(rePkhOut)) {
    return p2pkh({ pubkey: keyExpression2PubKey({ desc, network }), network })
      .address;
  }
  //nested segwit
  else if (desc.match(reShWpkhOut)) {
    return p2sh({
      redeem: p2wpkh({
        pubkey: keyExpression2PubKey({ desc, network }),
        network
      }),
      network
    }).address;
  }
  //native segwit
  else if (desc.match(reWpkhOut)) {
    return p2wpkh({ pubkey: keyExpression2PubKey({ desc, network }), network })
      .address;
  }
  //sh(wsh(miniscript))
  else if (desc.match(reShWshMiniscriptOut)) {
    const script = desc2Script({ desc, network });
    return p2sh({
      redeem: p2wsh({ redeem: { output: script }, network }),
      network
    }).address;
  }
  //sh(miniscript)
  else if (desc.match(reShMiniscriptOut)) {
    const script = desc2Script({ desc, network });
    return p2sh({ redeem: { output: script }, network }).address;
  }
  //wsh(miniscript)
  else if (desc.match(reWshMiniscriptOut)) {
    const script = desc2Script({ desc, network });
    return p2wsh({ redeem: { output: script }, network }).address;
  }
  throw new Error('Could not parse descriptor.');
}
