// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  getBitcoinLibOrThrow,
  isScureTransaction,
  toBIP32Interface,
  toECPairInterface,
  type ScureTransactionLike,
  type ECPairInterfaceLike,
  type BIP32InterfaceLike,
  type ScureHDKeyLike,
  type PsbtLike
} from './bitcoinLib';
import { toPsbt } from './psbt';
import { applyPR2137 } from './bitcoinjsHdPatch';
import { isTaprootInput, tapTweakHash } from './bitcoinjs-lib-internals';

function signInputSingleKey({
  psbt,
  index,
  ecpair
}: {
  psbt: PsbtLike;
  index: number;
  ecpair: ECPairInterfaceLike;
}): void {
  //psbt.signInput(index, ecpair); <- Replaced for the code below
  //that can handle taproot inputs automatically.
  //See https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
  const input = psbt.data.inputs[index];
  if (!input) throw new Error('Invalid index');
  if (isTaprootInput(input)) {
    // If script-path (tapLeafScript present) -> DO NOT TWEAK
    if (input.tapLeafScript && input.tapLeafScript.length > 0)
      psbt.signInput(index, ecpair);
    else {
      const hash = tapTweakHash(ecpair.publicKey.slice(1, 33), undefined);
      const tweakedEcpair = ecpair.tweak(hash);
      psbt.signInput(index, tweakedEcpair);
    }
  } else psbt.signInput(index, ecpair);
}

function signSingleKey({
  psbt,
  ecpair
}: {
  psbt: PsbtLike;
  ecpair: ECPairInterfaceLike;
}): void {
  let signedAny = false;
  for (let index = 0; index < psbt.data.inputs.length; index++) {
    try {
      signInputSingleKey({ psbt, index, ecpair });
      signedAny = true;
    } catch (err) {
      void err;
    }
  }
  if (!signedAny) throw new Error('No inputs were signed');
}

/**
 * Signs a specific input of a transaction with a bitcoinjs-lib `ECPair` signer.
 *
 * It detects Taproot inputs and applies key tweaking when needed before
 * signing.
 *
 * For `@scure/btc-signer` transactions and raw private keys, use
 * {@link signInputPrivKey}.
 *
 * @see https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - A bitcoinjs-lib
 * {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/psbt.ts | `Psbt`}.
 * @param {number} params.index - The input index to sign
 * @param {ECPairInterfaceLike} params.ecpair - A bitcoinjs
 * {@link https://github.com/bitcoinjs/ecpair | `ECPair`} signer.
 */
export function signInputECPair({
  psbt,
  index,
  ecpair
}: {
  psbt: PsbtLike;
  index: number;
  ecpair: ECPairInterfaceLike;
}): void {
  if (isScureTransaction(psbt))
    throw new Error(
      'Error: signInputECPair is only supported with bitcoinjs-lib PSBTs. ' +
        'Use signInputPrivKey for @scure/btc-signer transactions.'
    );
  signInputSingleKey({ psbt, index, ecpair });
}
/**
 * Signs all inputs of a transaction with a bitcoinjs-lib `ECPair` signer.
 *
 * For each input, it detects Taproot and applies key tweaking when needed
 * before signing.
 *
 * For `@scure/btc-signer` transactions and raw private keys, use
 * {@link signPrivKey}.
 *
 * @see https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - A bitcoinjs-lib
 * {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/psbt.ts | `Psbt`}.
 * @param {ECPairInterfaceLike} params.ecpair - A bitcoinjs
 * {@link https://github.com/bitcoinjs/ecpair | `ECPair`} signer.
 */
export function signECPair({
  psbt,
  ecpair
}: {
  psbt: PsbtLike;
  ecpair: ECPairInterfaceLike;
}): void {
  if (isScureTransaction(psbt))
    throw new Error(
      'Error: signECPair is only supported with bitcoinjs-lib PSBTs. ' +
        'Use signPrivKey for @scure/btc-signer transactions.'
    );
  signSingleKey({ psbt, ecpair });
}

/**
 * Signs one input of a `@scure/btc-signer` transaction with a raw private key.
 *
 * This helper is intended for scure users that work directly with a `Uint8Array`
 * private key and may not use bitcoinjs-lib `ECPair` types.
 *
 * If you are signing a bitcoinjs-lib PSBT input, use {@link signInputECPair}
 * and pass a bitcoinjs
 * {@link https://github.com/bitcoinjs/ecpair | `ECPair`} signer.
 *
 * @param {Object} params - The parameters object
 * @param {ScureTransactionLike} params.psbt - A scure
 * {@link https://github.com/paulmillr/scure-btc-signer | `Transaction`}.
 * @param {number} params.index - The input index to sign
 * @param {Uint8Array} params.privKey - The secp256k1 private key (32 bytes)
 * @throws If `psbt` is not a scure transaction
 */
export function signInputPrivKey({
  psbt,
  index,
  privKey
}: {
  psbt: ScureTransactionLike;
  index: number;
  privKey: Uint8Array;
}): void {
  if (!isScureTransaction(psbt)) {
    throw new Error(
      'Error: signInputPrivKey is only supported with @scure/btc-signer transactions. ' +
        'Use signInputECPair for bitcoinjs-lib PSBTs.'
    );
  }
  signInputSingleKey({
    psbt: toPsbt(psbt),
    index,
    ecpair: toECPairInterface(privKey)
  });
}

/**
 * Signs all inputs of a `@scure/btc-signer` transaction with a raw private key.
 *
 * This helper is intended for scure users that work directly with a `Uint8Array`
 * private key and may not use bitcoinjs-lib `ECPair` types.
 *
 * If you are signing a bitcoinjs-lib PSBT, use {@link signECPair} and pass a
 * bitcoinjs {@link https://github.com/bitcoinjs/ecpair | `ECPair`} signer.
 *
 * @param {Object} params - The parameters object
 * @param {ScureTransactionLike} params.psbt - A scure
 * {@link https://github.com/paulmillr/scure-btc-signer | `Transaction`}.
 * @param {Uint8Array} params.privKey - The secp256k1 private key (32 bytes)
 * @throws If `psbt` is not a scure transaction
 */
export function signPrivKey({
  psbt,
  privKey
}: {
  psbt: ScureTransactionLike;
  privKey: Uint8Array;
}): void {
  if (!isScureTransaction(psbt)) {
    throw new Error(
      'Error: signPrivKey is only supported with @scure/btc-signer transactions. ' +
        'Use signECPair for bitcoinjs-lib PSBTs.'
    );
  }
  signSingleKey({
    psbt: toPsbt(psbt),
    ecpair: toECPairInterface(privKey)
  });
}

/**
 * Signs one input of a transaction using an HD node.
 * Supports both bitcoinjs PSBT and scure Transaction inputs; bitcoinjs calls
 * also apply the local HD-signing compatibility patch before signing.
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike | ScureTransactionLike} params.psbt - Pass a
 * bitcoinjs-lib {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/psbt.ts | `Psbt`}
 * or a scure {@link https://github.com/paulmillr/scure-btc-signer | `Transaction`}.
 * @param {number} params.index - The input index to sign
 * @param {BIP32InterfaceLike | ScureHDKeyLike} params.node - Pass a bitcoinjs
 * {@link https://github.com/bitcoinjs/bip32 | `BIP32`} node or a scure
 * {@link https://github.com/paulmillr/scure-bip32 | `HDKey`} node.
 */
export function signInputBIP32({
  psbt,
  index,
  node
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  node: BIP32InterfaceLike | ScureHDKeyLike;
}): void {
  const bitcoinLib = getBitcoinLibOrThrow();
  node = toBIP32Interface(node);
  psbt = toPsbt(psbt);
  if (bitcoinLib.kind === 'bitcoinjs') applyPR2137(psbt);
  psbt.signInputHD(index, node);
}

/**
 * Signs all signable inputs of a transaction using an HD node.
 * Supports both bitcoinjs PSBT and scure Transaction inputs; bitcoinjs calls
 * also apply the local HD-signing compatibility patch before signing.
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike | ScureTransactionLike} params.psbt - Pass a
 * bitcoinjs-lib {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/psbt.ts | `Psbt`}
 * or a scure {@link https://github.com/paulmillr/scure-btc-signer | `Transaction`}.
 * @param {BIP32InterfaceLike | ScureHDKeyLike} params.masterNode - Pass a
 * bitcoinjs {@link https://github.com/bitcoinjs/bip32 | `BIP32`} node or a
 * scure {@link https://github.com/paulmillr/scure-bip32 | `HDKey`} node.
 */
export function signBIP32({
  psbt,
  masterNode
}: {
  psbt: PsbtLike | ScureTransactionLike;
  masterNode: BIP32InterfaceLike | ScureHDKeyLike;
}): void {
  const bitcoinLib = getBitcoinLibOrThrow();
  masterNode = toBIP32Interface(masterNode);
  psbt = toPsbt(psbt);
  if (bitcoinLib.kind === 'bitcoinjs') applyPR2137(psbt);
  psbt.signAllInputsHD(masterNode);
}
