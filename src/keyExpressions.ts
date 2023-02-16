// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { networks, Network } from 'bitcoinjs-lib';
import type { ECPairAPI, ECPairInterface } from 'ecpair';
import type { BIP32API, BIP32Interface } from 'bip32';
import type { KeyInfo } from './types';

import * as RE from './re';

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

/*
 * Takes a key expression (xpub, xprv, pubkey or wif) and returns a pubkey in
 * binary format
 */
export function parseKeyExpression({
  keyExpression,
  isSegwit,
  ECPair,
  BIP32,
  network = networks.bitcoin
}: {
  keyExpression: string;
  network?: Network;
  isSegwit?: boolean;
  ECPair: ECPairAPI;
  BIP32: BIP32API;
}): KeyInfo {
  let pubkey: Buffer;
  let ecpair: ECPairInterface | undefined;
  let bip32: BIP32Interface | undefined;
  let masterFingerprint: Buffer | undefined;
  let originPath: string | undefined;
  let keyPath: string | undefined;
  let path: string | undefined;

  //Validate the keyExpression:
  const keyExpressions = keyExpression.match(RE.reKeyExp);
  if (keyExpressions === null || keyExpressions[0] !== keyExpression) {
    throw new Error(`Error: expected a keyExpression but got ${keyExpression}`);
  }

  const reOriginAnchoredStart = RegExp(String.raw`^(${RE.reOrigin})?`); //starts with ^origin
  const mOrigin = keyExpression.match(reOriginAnchoredStart);
  if (mOrigin) {
    const bareOrigin = mOrigin[0].replace(/[\[\]]/g, ''); //strip the "[" and "]" in [origin]
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
      masterFingerprint = Buffer.from(masterFingerprintHex, 'hex');
    }
  }

  //Remove the origin (if it exists) and store result in actualKey
  const actualKey = keyExpression.replace(reOriginAnchoredStart, '');
  let mPubKey, mWIF, mXpubKey, mXprvKey;
  //match pubkey:
  if ((mPubKey = actualKey.match(RE.anchorStartAndEnd(RE.rePubKey))) !== null) {
    pubkey = Buffer.from(mPubKey[0], 'hex');
    ecpair = ECPair.fromPublicKey(pubkey, { network });
    //Validate the pubkey (compressed or uncompressed)
    if (
      !ECPair.isPoint(pubkey) ||
      !(pubkey.length === 33 || pubkey.length === 65)
    ) {
      throw new Error(`Error: invalid pubkey`);
    }
    //Do an extra check in case we know this pubkey refers to a segwit input
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
    //match xpub:
  } else if (
    (mXpubKey = actualKey.match(RE.anchorStartAndEnd(RE.reXpubKey))) !== null
  ) {
    const xPubKey = mXpubKey[0];
    const xPub = xPubKey.match(RE.reXpub)?.[0];
    if (!xPub) throw new Error(`Error: xpub could not be matched`);
    bip32 = BIP32.fromBase58(xPub, network);
    const mPath = xPubKey.match(RE.rePath);
    if (mPath !== null) {
      keyPath = xPubKey.match(RE.rePath)?.[0];
      if (!keyPath) throw new Error(`Error: could not extract a path`);
      //fromBase58 and derivePath will throw if xPub or path are not valid
      pubkey = derivePath(bip32, keyPath).publicKey;
    } else {
      pubkey = bip32.publicKey;
    }
    //match xprv:
  } else if (
    (mXprvKey = actualKey.match(RE.anchorStartAndEnd(RE.reXprvKey))) !== null
  ) {
    const xPrvKey = mXprvKey[0];
    const xPrv = xPrvKey.match(RE.reXprv)?.[0];
    if (!xPrv) throw new Error(`Error: xprv could not be matched`);
    bip32 = BIP32.fromBase58(xPrv, network);
    const mPath = xPrvKey.match(RE.rePath);
    if (mPath !== null) {
      keyPath = xPrvKey.match(RE.rePath)?.[0];
      if (!keyPath) throw new Error(`Error: could not extract a path`);
      //fromBase58 and derivePath will throw if xPrv or path are not valid
      pubkey = derivePath(bip32, keyPath).publicKey;
    } else {
      pubkey = bip32.publicKey;
    }
  } else {
    throw new Error(
      `Error: could not get pubkey for keyExpression ${keyExpression}`
    );
  }
  if (masterFingerprint && (originPath || keyPath)) {
    path = 'm' + originPath + keyPath;
  }
  return {
    pubkey,
    keyExpression,
    ...(ecpair !== undefined ? { ecpair } : {}),
    ...(bip32 !== undefined ? { bip32 } : {}),
    ...(masterFingerprint !== undefined ? { masterFingerprint } : {}),
    ...(originPath !== undefined && originPath !== '' ? { originPath } : {}),
    ...(keyPath !== undefined && keyPath !== '' ? { keyPath } : {}),
    ...(path !== undefined ? { path } : {})
  };
}
