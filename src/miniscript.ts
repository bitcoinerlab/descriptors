// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { networks, script as bscript, crypto, Network } from 'bitcoinjs-lib';
import type { ECPairAPI } from 'ecpair';
import type { BIP32API } from 'bip32';
import { parseKeyExpression } from './keyExpressions';
import * as RE from './re';
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
  isTaproot,
  network = networks.bitcoin,
  ECPair,
  BIP32
}: {
  miniscript: string;
  isSegwit: boolean;
  isTaproot: boolean;
  network?: Network;
  ECPair: ECPairAPI;
  BIP32: BIP32API;
}): {
  expandedMiniscript: string;
  expansionMap: ExpansionMap;
} {
  if (isTaproot) throw new Error('Taproot miniscript not yet supported.');

  miniscript = preprocessSortedMulti(
    miniscript,
    isSegwit,
    isTaproot,
    network,
    ECPair,
    BIP32
  );

  const reKeyExp = isTaproot
    ? RE.reTaprootKeyExp
    : isSegwit
      ? RE.reSegwitKeyExp
      : RE.reNonSegwitKeyExp;
  const expansionMap: ExpansionMap = {};
  const expandedMiniscript = miniscript.replace(
    RegExp(reKeyExp, 'g'),
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
  //keyExpressions must produce a valid pubkey (unless it's ranged and we want
  //to expand a generalized form, then we don't check)
  const pubkeysHex: string[] = Object.values(expansionMap)
    .filter(keyInfo => keyInfo.keyExpression.indexOf('*') === -1)
    .map(keyInfo => {
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

function sortPublicKeysFromExpressions(
  keyExpressions: string[],
  isSegwit: boolean,
  isTaproot: boolean,
  network: Network,
  ECPair: ECPairAPI,
  BIP32: BIP32API
): string[] {
  const keyInfos = keyExpressions.map(keyExpression => {
    const keyInfo = parseKeyExpression({
      keyExpression,
      isSegwit,
      isTaproot,
      network,
      ECPair,
      BIP32
    });
    if (!keyInfo.pubkey) {
      throw new Error(
        `Error: keyExpression ${keyExpression} does not have a pubkey`
      );
    }
    return { keyExpression, pubkey: keyInfo.pubkey };
  });

  keyInfos.sort((a, b) => a.pubkey.compare(b.pubkey));

  return keyInfos.map(info => info.keyExpression);
}

function preprocessSortedMulti(
  miniscript: string,
  isSegwit: boolean,
  isTaproot: boolean,
  network: Network,
  ECPair: ECPairAPI,
  BIP32: BIP32API
): string {
  const sortedMultiRegex = /sortedmulti\(\s*(\d+)\s*,\s*([^)]+)\s*\)/g;
  return miniscript.replace(sortedMultiRegex, (_match, threshold, keysStr) => {
    const keyExpressions = keysStr.split(',').map((k: string) => k.trim());
    const sortedKeys = sortPublicKeysFromExpressions(
      keyExpressions,
      isSegwit,
      isTaproot,
      network,
      ECPair,
      BIP32
    );
    return `multi(${threshold},${sortedKeys.join(',')})`;
  });
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
        `<HASH160(${key})>`,
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
    .replace(/(<\d+>)|\b\d+\b/g, match =>
      match.startsWith('<') ? match : numberEncodeAsm(Number(match))
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

/**
 * Assumptions:
 * The attacker does not have access to any of the private keys of public keys
 * that participate in the Script.
 *
 * The attacker only has access to hash preimages that honest users have access
 * to as well.
 *
 * Pass timeConstraints to search for the first solution with this nLockTime and
 * nSequence. Throw if no solution is possible using these constraints.
 *
 * Don't pass timeConstraints (this is the default) if you want to get the
 * smallest size solution altogether.
 *
 * If a solution is not found this function throws.
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
  const preimageMap: { [key: string]: string } = {};
  preimages.forEach(preimage => {
    preimageMap['<' + preimage.digest.replace('(', '_preimage(') + '>'] =
      '<' + preimage.preimage + '>';
  });

  //convert the pubkeys in signatures into [{['<sig(@0)>']: '30450221'}, ...]
  //get the keyExpressions: @0, @1 from the keys in expansionMap
  const expandedSignatureMap: { [key: string]: string } = {};
  signatures.forEach(signature => {
    const pubkeyHex = signature.pubkey.toString('hex');
    const keyExpression = Object.keys(expansionMap).find(
      k => expansionMap[k]?.pubkey?.toString('hex') === pubkeyHex
    );
    expandedSignatureMap['<sig(' + keyExpression + ')>'] =
      '<' + signature.signature.toString('hex') + '>';
  });
  const expandedKnownsMap = { ...preimageMap, ...expandedSignatureMap };
  const knowns = Object.keys(expandedKnownsMap);

  //satisfier verifies again internally whether expandedKnownsMap with given knowns is sane
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

/**
 *
 * Use this function instead of bitcoinjs-lib's equivalent `script.number.encode`
 * when encoding numbers to be compiled with `fromASM` to avoid problems.
 *
 * Motivation:
 *
 * Numbers in Bitcoin assembly code are represented in hex and in Little Endian.
 * Decimal: 32766 - Big endian: 0x7FFE - Little Endian: 0xFE7F.
 *
 * This function takes an integer and encodes it so that bitcoinjs-lib `fromASM`
 * can compile it. This is basically what bitcoinjs-lib's `script.number.encode`
 * does.
 *
 * Note that `fromASM` already converts integers from 1 to 16 to
 * OP_1 ... OP_16 {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/59b21162a2c4645c64271ca004c7a3755a3d72fb/src/script.js#L33 here}.
 * This is done in Bitcoin to save some bits.
 *
 * Neither this function nor `script.number.encode` convert numbers to
 * their op code equivalent since this is done later in `fromASM`.
 *
 * Both functions simply convert numbers to Little Endian.
 *
 * However, the `0` number is an edge case that we specially handle with this
 * function.
 *
 * bitcoinjs-lib's `bscript.number.encode(0)` produces an empty Buffer.
 * This is what the Bitcoin interpreter does and it is what `script.number.encode` was
 * implemented to do.
 *
 * The problem is `bscript.number.encode(0).toString('hex')` produces an
 * empty string and thus it should not be used to serialize number zero before `fromASM`.
 *
 * A zero should produce the OP_0 ASM symbolic code (corresponding to a `0` when
 * compiled).
 *
 * So, this function will produce a string in hex format in Little Endian
 * encoding for integers not equal to `0` and it will return `OP_0` for `0`.
 *
 * Read more about the this {@link https://github.com/bitcoinjs/bitcoinjs-lib/issues/1799#issuecomment-1122591738 here}.
 *
 * Use it in combination with `fromASM` like this:
 *
 * ```javascript
 * //To produce "0 1 OP_ADD":
 * fromASM(
 * `${numberEncodeAsm(0)} ${numberEncodeAsm(1)} OP_ADD`
 *   .trim().replace(/\s+/g, ' ')
 * )
 * ```
 *
 * @param {number} number An integer.
 * @returns {string} Returns `"OP_0"` for `number === 0` and a hex string representing other numbers in Little Endian encoding.
 */
export function numberEncodeAsm(number: number) {
  if (Number.isSafeInteger(number) === false) {
    throw new Error(`Error: invalid number ${number}`);
  }
  if (number === 0) {
    return 'OP_0';
  } else return bscript.number.encode(number).toString('hex');
}
