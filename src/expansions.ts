//TODO: rename this file miniscript
import { networks, script as bscript, crypto, Network } from 'bitcoinjs-lib';
import type { ECPairAPI } from 'ecpair';
import type { BIP32API } from 'bip32';
import { parseKeyExpression } from './keyExpressions';
import * as RE from './re';
import { numberEncodeAsm } from './numberEncodeAsm';
import type { PartialSig } from 'bip174/src/lib/interfaces';
import { compileMiniscript, satisfier } from '@bitcoinerlab/miniscript';
import type { Preimage, TimeConstraints, ExpansionMap } from './types';

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
function substituteAsm({
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

//TODO - this is in fact returning  a union of type TimeConstraints with a Buffer
/**
 * Assumptions:
 * The attacker does not have access to any of the private keys of public keys that participate in the Script.
 * The attacker only has access to hash preimages that honest users have access to as well.
 *
 * Pass timeConstraints to search for the first solution with this nLockTime and nSequence.
 * Don't pass timeConstraints (this is the default) if you want to get the smallest size solution altogether.
 *
 * It a solution is not found this function throws.
 */
export function satisfyMiniscript({
  expandedMiniscript,
  expansionMap,
  signatures = [],
  preimages = [],
  timeConstraints
}: {
  expandedMiniscript: string;
  expansionMap: ExpansionMap;
  signatures?: PartialSig[];
  preimages?: Preimage[];
  timeConstraints?: TimeConstraints;
}): {
  scriptSatisfaction: Buffer;
  nLockTime: number | undefined;
  nSequence: number | undefined;
} {
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
    const pubkeyHex = signature.pubkey.toString('hex');
    const keyExpression = Object.keys(expansionMap).find(
      k => expansionMap[k]?.pubkey.toString('hex') === pubkeyHex
    );
    expandedSignatureMap['<sig(' + keyExpression + ')>'] =
      '<' + signature.signature.toString('hex') + '>';
  });
  const expandedKnownsMap = { ...preimageMap, ...expandedSignatureMap };
  const knowns = Object.keys(expandedKnownsMap);

  //TODO: Move the TimeConstraints definition there
  //TODO: Add a Satisfaction type for : Array<{ asm: string; nLockTime?: number; nSequence?: number; }> in miniscript that is an extension (union type) to TimeConstraints
  const { nonMalleableSats } = satisfier(expandedMiniscript, { knowns });

  if (!Array.isArray(nonMalleableSats) || !nonMalleableSats[0])
    throw new Error(`Error: unresolvable miniscript ${expandedMiniscript}`);

  let sat;
  if (!timeConstraints) {
    sat = nonMalleableSats[0];
  } else {
    sat = nonMalleableSats.find(
      nonMalleableSat =>
        nonMalleableSat.nSequence === timeConstraints.nSequence &&
        nonMalleableSat.nLockTime === timeConstraints.nLockTime
    );
    if (sat === undefined) {
      throw new Error(
        `Error: unresolvable miniscript ${expandedMiniscript}. Could not find solutions for sequence ${timeConstraints.nSequence} & locktime=${timeConstraints.nLockTime}. Signatures are applied to a hash that depends on sequence and locktime. Did you provide all the signatures wrt the signers keys declared and include all preimages?`
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
