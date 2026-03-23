// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type {
  ECPairAPILike,
  BIP32APILike,
  ECPairInterfaceLike,
  BIP32InterfaceLike,
  ScureHDKeyLike
} from './bitcoinLib';
import { type Network, networks } from './networks';
import type { KeyInfo } from './types';
import {
  LedgerManager,
  getLedgerMasterFingerPrint,
  getLedgerXpub
} from './ledger';
import { toBIP32Interface } from './keyInterfaces';
import { concat, fromHex, toHex } from 'uint8array-tools';

import * as RE from './re';

const derivePath = (node: BIP32InterfaceLike, path: string) => {
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
 * Parses a key expression (xpub, xprv, pubkey or wif) into {@link KeyInfo | `KeyInfo`}.
 *
 * For example, given this `keyExpression`: `"[d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*"`, this is its parsed result:
 *
 * ```javascript
 *  {
 *    keyExpression:
 *      "[d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*",
 *    keyPath: '/1/2/3/4/*',
 *    originPath: "/49'/0'/0'",
 *    path: "m/49'/0'/0'/1/2/3/4/*",
 *    // Other relevant properties of `KeyInfo`: `pubkey`, `ecpair`, `bip32`,
 *    // `privkey`, `xPub`, `xPrv`, `masterFingerprint`, etc.
 *  }
 * ```
 */
export function parseKeyExpression({
  keyExpression,
  isSegwit,
  isTaproot,
  ECPair,
  BIP32,
  network = networks.bitcoin
}: {
  keyExpression: string;
  /** @default networks.bitcoin */
  network?: Network;
  /**
   * Indicates if this key expression belongs to a a SegWit output. When set,
   * further checks are done to ensure the public key (if present in the
   * expression) is compressed (33 bytes).
   */
  isSegwit?: boolean;
  /**
   * Indicates if this key expression belongs to a Taproot output. For Taproot,
   * the key must be represented as an x-only public key (32 bytes).
   * If a 33-byte compressed pubkey is derived, it is converted to its x-only
   * representation.
   */
  isTaproot?: boolean;
  ECPair: ECPairAPILike;
  BIP32: BIP32APILike;
}): KeyInfo {
  if (isTaproot && isSegwit !== true)
    throw new Error(`Error: taproot key expressions require isSegwit`);
  let pubkey: Uint8Array | undefined; //won't be computed for ranged keyExpressions
  let ecpair: ECPairInterfaceLike | undefined;
  let bip32: BIP32InterfaceLike | undefined;
  let privkey: Uint8Array | undefined;
  let xPub: string | undefined;
  let xPrv: string | undefined;
  let masterFingerprint: Uint8Array | undefined;
  let originPath: string | undefined;
  let keyPath: string | undefined;
  let path: string | undefined;

  const isRanged = keyExpression.indexOf('*') !== -1;
  const reKeyExp = isTaproot
    ? RE.reTaprootKeyExp
    : isSegwit
      ? RE.reSegwitKeyExp
      : RE.reNonSegwitKeyExp;
  const rePubKey = isTaproot
    ? RE.reTaprootPubKey
    : isSegwit
      ? RE.reSegwitPubKey
      : RE.reNonSegwitPubKey;
  //Validate the keyExpression:
  const keyExpressions = keyExpression.match(reKeyExp);
  if (keyExpressions === null || keyExpressions[0] !== keyExpression) {
    throw new Error(`Error: expected a keyExpression but got ${keyExpression}`);
  }

  const reOriginAnchoredStart = RegExp(String.raw`^(${RE.reOrigin})?`); //starts with ^origin
  const mOrigin = keyExpression.match(reOriginAnchoredStart);
  if (mOrigin) {
    const bareOrigin = mOrigin[0].replace(/[[\]]/g, ''); //strip the "[" and "]" in [origin]
    const reMasterFingerprintAnchoredStart = String.raw`^(${RE.reMasterFingerprint})`;
    const mMasterFingerprint = bareOrigin.match(
      reMasterFingerprintAnchoredStart
    );
    const masterFingerprintHex = mMasterFingerprint
      ? mMasterFingerprint[0]
      : '';
    originPath = bareOrigin.replace(masterFingerprintHex, '');
    if (masterFingerprintHex.length > 0) {
      if (masterFingerprintHex.length !== 8)
        throw new Error(
          `Error: masterFingerprint ${masterFingerprintHex} invalid for keyExpression: ${keyExpression}`
        );
      masterFingerprint = fromHex(masterFingerprintHex);
    }
  }

  //Remove the origin (if it exists) and store result in actualKey
  const actualKey = keyExpression.replace(reOriginAnchoredStart, '');
  let mPubKey, mWIF, mXpubKey, mXprvKey;
  //match pubkey:
  if ((mPubKey = actualKey.match(RE.anchorStartAndEnd(rePubKey))) !== null) {
    pubkey = fromHex(mPubKey[0]);
    if (isTaproot && pubkey.length === 32)
      //convert the xonly point to a compressed point assuming even parity
      pubkey = concat([Uint8Array.from([0x02]), pubkey]);

    ecpair = ECPair.fromPublicKey(pubkey, { network });
    //Validate the pubkey (compressed or uncompressed)
    if (
      !ECPair.isPoint(pubkey) ||
      !(pubkey.length === 33 || pubkey.length === 65)
    ) {
      throw new Error(`Error: invalid pubkey`);
    }
    //Do an extra check in case we know this pubkey refers to a segwit input
    //Taproot x-only keys are converted to 33-byte compressed form above.
    if (
      typeof isSegwit === 'boolean' &&
      isSegwit &&
      pubkey.length !== 33 //Inside wpkh and wsh, only compressed public keys are permitted.
    ) {
      throw new Error(`Error: invalid pubkey`);
    }
    //match WIF:
  } else if (
    (mWIF = actualKey.match(RE.anchorStartAndEnd(RE.reWIF))) !== null
  ) {
    ecpair = ECPair.fromWIF(mWIF[0], network);
    //fromWIF will throw if the wif is not valid
    pubkey = ecpair.publicKey;
    privkey = ecpair.privateKey;
    //match xpub:
  } else if (
    (mXpubKey = actualKey.match(RE.anchorStartAndEnd(RE.reXpubKey))) !== null
  ) {
    const xPubKey = mXpubKey[0];
    xPub = xPubKey.match(RE.reXpub)?.[0];
    if (!xPub) throw new Error(`Error: xpub could not be matched`);
    bip32 = BIP32.fromBase58(xPub, network);
    const mPath = xPubKey.match(RE.rePath);
    if (mPath !== null) {
      keyPath = xPubKey.match(RE.rePath)?.[0];
      if (!keyPath) throw new Error(`Error: could not extract a path`);
      //fromBase58 and derivePath will throw if xPub or path are not valid
      if (!isRanged) pubkey = derivePath(bip32, keyPath).publicKey;
    } else {
      pubkey = bip32.publicKey;
    }
    //match xprv:
  } else if (
    (mXprvKey = actualKey.match(RE.anchorStartAndEnd(RE.reXprvKey))) !== null
  ) {
    const xPrvKey = mXprvKey[0];
    xPrv = xPrvKey.match(RE.reXprv)?.[0];
    if (!xPrv) throw new Error(`Error: xprv could not be matched`);
    bip32 = BIP32.fromBase58(xPrv, network);
    xPub = bip32.neutered().toBase58();
    const mPath = xPrvKey.match(RE.rePath);
    if (mPath !== null) {
      keyPath = xPrvKey.match(RE.rePath)?.[0];
      if (!keyPath) throw new Error(`Error: could not extract a path`);
      //fromBase58 and derivePath will throw if xPrv or path are not valid
      if (!isRanged) pubkey = derivePath(bip32, keyPath).publicKey;
    } else {
      pubkey = bip32.publicKey;
    }
  } else {
    throw new Error(
      `Error: could not get pubkey for keyExpression ${keyExpression}`
    );
  }
  if (originPath || keyPath) {
    path = `m${originPath ?? ''}${keyPath ?? ''}`;
  }
  if (pubkey !== undefined) {
    if (isTaproot) {
      if (pubkey.length !== 33) throw new Error(`Error: invalid pubkey`);
    } else if (
      typeof isSegwit === 'boolean' &&
      isSegwit &&
      pubkey.length !== 33
    ) {
      throw new Error(`Error: invalid pubkey`);
    }
  }
  if (pubkey !== undefined && isTaproot && pubkey.length === 33)
    // If we get a 33-byte compressed key, drop the first byte.
    pubkey = pubkey.slice(1, 33);

  return {
    keyExpression,
    ...(pubkey !== undefined ? { pubkey } : {}),
    ...(ecpair !== undefined ? { ecpair } : {}),
    ...(bip32 !== undefined ? { bip32 } : {}),
    ...(privkey !== undefined ? { privkey } : {}),
    ...(xPub !== undefined ? { xPub } : {}),
    ...(xPrv !== undefined ? { xPrv } : {}),
    ...(masterFingerprint !== undefined ? { masterFingerprint } : {}),
    ...(originPath !== undefined && originPath !== '' ? { originPath } : {}),
    ...(keyPath !== undefined && keyPath !== '' ? { keyPath } : {}),
    ...(path !== undefined ? { path } : {})
  };
}

function assertChangeIndexKeyPath({
  change,
  index,
  keyPath
}: {
  change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string | undefined; //In the case of the Ledger, keyPath must be /<1;0>/number
}) {
  if (
    !(
      (change === undefined && index === undefined) ||
      (change !== undefined && index !== undefined)
    )
  )
    throw new Error(`Error: Pass change and index or neither`);
  if ((change !== undefined) === (keyPath !== undefined))
    throw new Error(`Error: Pass either change and index or a keyPath`);
}

/**
 * Constructs a key expression string for a Ledger device from the provided
 * components.
 *
 * This function assists in crafting key expressions tailored for Ledger
 * hardware wallets. It fetches the master fingerprint and xpub for a
 * specified origin path and then combines them with the input parameters.
 *
 * For detailed understanding and examples of terms like `originPath`,
 * `change`, and `keyPath`, refer to the documentation of
 * {@link KeyExpressionParser}, which consists
 * of the reverse procedure.
 *
 * @returns {Promise<string>} - The formed key expression for the Ledger device.
 */
export async function keyExpressionLedger({
  ledgerManager,
  originPath,
  keyPath,
  change,
  index
}: {
  ledgerManager: LedgerManager;
  originPath: string;
  change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string | undefined; //In the case of the Ledger, keyPath must be /<1;0>/number
}): Promise<string>;
export async function keyExpressionLedger({
  ledgerManager,
  originPath,
  keyPath,
  change,
  index
}: {
  ledgerManager: LedgerManager;
  originPath: string;
  change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string | undefined; //In the case of the Ledger, keyPath must be /<1;0>/number
}) {
  assertChangeIndexKeyPath({ change, index, keyPath });

  const masterFingerprint = await getLedgerMasterFingerPrint({
    ledgerManager
  });
  const origin = `[${toHex(masterFingerprint)}${originPath}]`;
  const xpub = await getLedgerXpub({ originPath, ledgerManager });

  const keyRoot = `${origin}${xpub}`;
  if (keyPath !== undefined) return `${keyRoot}${keyPath}`;
  else return `${keyRoot}/${change}/${index}`;
}

/**
 * Constructs a BIP32 key expression string from its constituent components.
 *
 * This function essentially performs the reverse operation of
 * {@link KeyExpressionParser}. For detailed
 * explanations and examples of the terms used here, refer to
 * {@link KeyExpressionParser}.
 *
 * @param {Object} params - The parameters object.
 * @param {BIP32InterfaceLike | ScureHDKeyLike} params.masterNode - Root HD node.
 * Pass either:
 * - a bitcoinjs {@link https://github.com/bitcoinjs/bip32 | `BIP32`} node, or
 * - a scure {@link https://github.com/paulmillr/scure-bip32 | `HDKey`}.
 * @param {string} params.originPath - Origin path from master, e.g. `"/84'/0'/0'"`.
 * @param {number} [params.change] - Branch index (`0` receive, `1` change).
 * @param {number | '*'} [params.index] - Address index or `*` for ranged descriptors.
 * @param {string} [params.keyPath] - Full suffix path (`/change/index`) alternative to
 * `change` + `index`.
 * @returns {string} Descriptor key expression (e.g. `[f23f9fd2/84'/0'/0']xpub.../0/5`).
 *
 * @example
 * ```ts
 * import * as ecc from '@bitcoinerlab/secp256k1';
 * import { BIP32Factory } from 'bip32';
 * import { keyExpressionBIP32 } from '@bitcoinerlab/descriptors';
 *
 * const BIP32 = BIP32Factory(ecc);
 * const masterNode = BIP32.fromSeed(seedBytes);
 * const keyExp = keyExpressionBIP32({
 *   masterNode,
 *   originPath: "/84'/0'/0'",
 *   change: 0,
 *   index: 5
 * });
 * ```
 *
 * @example
 * ```ts
 * import { HDKey } from '@scure/bip32';
 * import { keyExpressionBIP32 } from '@bitcoinerlab/descriptors';
 *
 * const masterNode = HDKey.fromMasterSeed(seedBytes);
 * const keyExp = keyExpressionBIP32({
 *   masterNode,
 *   originPath: "/84'/0'/0'",
 *   keyPath: '/0/*'
 * });
 * ```
 */
export function keyExpressionBIP32({
  masterNode,
  originPath,
  keyPath,
  change,
  index,
  isPublic = true
}: {
  masterNode: BIP32InterfaceLike | ScureHDKeyLike;
  originPath: string;
  change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string | undefined; //In the case of the Ledger, keyPath must be /<1;0>/number
  /**
   * Compute an xpub or xprv
   * @default true
   */
  isPublic?: boolean;
}) {
  masterNode = toBIP32Interface(masterNode);
  assertChangeIndexKeyPath({ change, index, keyPath });
  const masterFingerprint = masterNode.fingerprint;
  const origin = `[${toHex(masterFingerprint)}${originPath}]`;
  const xpub = isPublic
    ? masterNode.derivePath(`m${originPath}`).neutered().toBase58().toString()
    : masterNode.derivePath(`m${originPath}`).toBase58().toString();

  const keyRoot = `${origin}${xpub}`;
  if (keyPath !== undefined) return `${keyRoot}${keyPath}`;
  else return `${keyRoot}/${change}/${index}`;
}
