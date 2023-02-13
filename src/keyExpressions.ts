//import {
//  networks,
//  Network,
//} from 'bitcoinjs-lib';
//export function parseKeyExpression({
//  keyExpression,
//  network = networks.bitcoin,
//  isSegwit = true
//}: {
//  keyExpression: string;
//  network?: Network;
//  isSegwit?: boolean;
//}): Buffer {
//  //Validate the keyExpression:
//  const keyExpressions = keyExpression.match(reKeyExp);
//  if (keyExpressions === null || keyExpressions[0] !== keyExpression) {
//    throw new Error(`Error: expected a keyExpression but got ${keyExpression}`);
//  }
//  //Remove the origin (if it exists) and store result in actualKey
//  const actualKey = keyExpression.replace(
//    RegExp(String.raw`^(${reOrigin})?`),
//    ''
//  ); //starts with ^origin
//  let mPubKey, mWIF, mXpubKey, mXprvKey;
//  //match pubkey:
//  if ((mPubKey = actualKey.match(anchorStartAndEnd(rePubKey))) !== null) {
//    const pubkey = Buffer.from(mPubKey[0], 'hex');
//    //Validate the pubkey (compressed or uncompressed)
//    if (
//      !ecc.isPoint(pubkey) ||
//      (isSegwit && pubkey.length !== 33) || //Inside wpkh and wsh, only compressed public keys are permitted.
//      !(pubkey.length === 33 || pubkey.length === 65)
//    ) {
//      throw new Error(`Error: invalid pubkey`);
//    } else {
//      return pubkey;
//    }
//    //match WIF:
//  } else if ((mWIF = actualKey.match(anchorStartAndEnd(reWIF))) !== null) {
//    //fromWIF will throw if the wif is not valid
//    return ecpair.fromWIF(mWIF[0], network).publicKey;
//    //match xpub:
//  } else if (
//    (mXpubKey = actualKey.match(anchorStartAndEnd(reXpubKey))) !== null
//  ) {
//    const xPubKey = mXpubKey[0];
//    const xPub = xPubKey.match(reXpub)?.[0];
//    if (!xPub) throw new Error(`Error: xpub could not be matched`);
//    const mPath = xPubKey.match(rePath);
//    if (mPath !== null) {
//      const path = xPubKey.match(rePath)?.[0];
//      if (!path) throw new Error(`Error: could not extract a path`);
//      //fromBase58 and derivePath will throw if xPub or path are not valid
//      return derivePath(bip32.fromBase58(xPub, network), path).publicKey;
//    } else {
//      return bip32.fromBase58(xPub, network).publicKey;
//    }
//    //match xprv:
//  } else if (
//    (mXprvKey = actualKey.match(anchorStartAndEnd(reXprvKey))) !== null
//  ) {
//    const xPrvKey = mXprvKey[0];
//    const xPrv = xPrvKey.match(reXprv)?.[0];
//    if (!xPrv) throw new Error(`Error: xprv could not be matched`);
//    const mPath = xPrvKey.match(rePath);
//    if (mPath !== null) {
//      const path = xPrvKey.match(rePath)?.[0];
//      if (!path) throw new Error(`Error: could not extract a path`);
//      //fromBase58 and derivePath will throw if xPrv or path are not valid
//      return derivePath(bip32.fromBase58(xPrv, network), path).publicKey;
//    } else {
//      return bip32.fromBase58(xPrv, network).publicKey;
//    }
//  } else {
//    throw new Error(
//      `Error: could not get pubkey for keyExpression ${keyExpression}`
//    );
//  }
//}
