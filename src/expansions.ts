import { networks, script as bscript, crypto, Network } from 'bitcoinjs-lib';
import type { ECPairAPI } from 'ecpair';
import type { BIP32API } from 'bip32';
import { parseKeyExpression, KeyInfo } from './keyExpressions';
import * as RE from './re';
import { numberEncodeAsm } from './numberEncodeAsm';
export interface ExpansionMap {
  //key will have this format: @i, where i is an integer
  [key: string]: KeyInfo;
}
import { compileMiniscript } from '@bitcoinerlab/miniscript';
/**
 * Expand a miniscript to a generalized form using variables instead of key
 * expressions. Variables will be of this form: @0, @1, ...
 * This is done so that it can be compiled with compileMiniscript and
 * satisfied with satisfier.
 * Also compute pubkeys from descriptors to use them later.
 */
export function expandMiniscript({
  miniscript,
  isSegwit,
  network = networks.bitcoin,
  ECPair,
  BIP32
}: {
  miniscript: string;
  isSegwit: boolean;
  network?: Network;
  ECPair: ECPairAPI;
  BIP32: BIP32API;
}): {
  expandedMiniscript: string;
  expansionMap: ExpansionMap;
} {
  const expansionMap: ExpansionMap = {};
  const expandedMiniscript = miniscript.replace(
    RegExp(RE.reKeyExp, 'g'),
    (keyExpression: string) => {
      const key = '@' + Object.keys(expansionMap).length;
      expansionMap[key] = parseKeyExpression({
        keyExpression,
        isSegwit,
        network,
        ECPair,
        BIP32
      });
      return key;
    }
  );

  //Do some assertions. Miniscript must not have duplicate keys, also all
  //keyExpressions must produce a valid pubkey
  const pubkeysHex: string[] = Object.values(expansionMap).map(keyInfo => {
    if (!keyInfo.pubkey)
      throw new Error(
        `Error: keyExpression ${keyInfo.keyExpression} does not have a pubkey`
      );
    return keyInfo.pubkey.toString('hex');
  });
  if (new Set(pubkeysHex).size !== pubkeysHex.length) {
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
export function substituteAsm({
  expandedAsm,
  expansionMap
}: {
  expandedAsm: string;
  expansionMap: ExpansionMap;
}): string {
  //Replace back variables into the pubkeys previously computed.
  let asm = Object.keys(expansionMap).reduce((accAsm, key) => {
    const pubkey = expansionMap[key]?.pubkey;
    if (!pubkey) {
      throw new Error(`Error: invalid expansionMap for ${key}`);
    }
    return accAsm
      .replaceAll(`<${key}>`, `<${pubkey.toString('hex')}>`)
      .replaceAll(
        `<HASH160\(${key}\)>`,
        `<${crypto.hash160(pubkey).toString('hex')}>`
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

//TODO: refactor - move from here
export function miniscript2Script({
  expandedMiniscript,
  expansionMap
}: {
  expandedMiniscript: string;
  expansionMap: ExpansionMap;
}): Buffer {
  const compiled = compileMiniscript(expandedMiniscript);
  if (compiled.issane !== true) {
    throw new Error(`Error: Miniscript ${expandedMiniscript} is not sane`);
  }
  return bscript.fromASM(
    substituteAsm({ expandedAsm: compiled.asm, expansionMap })
  );
}
