// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type {
  PsbtInput,
  Bip32Derivation,
  TapBip32Derivation,
  TapLeafScript
} from 'bip174';
import type { KeyInfo } from './types';
import type {
  Network,
  Payment,
  PsbtLike,
  ParsedTransaction,
  FinalScriptsFunc,
  BitcoinLib
} from './bitcoinLib';
import { compare, fromHex } from 'uint8array-tools';
import { witnessStackToScriptWitness } from './bitcoinjs-lib-internals';

interface PsbtInputExtended extends PsbtInput {
  hash: Uint8Array;
  index: number;
  sequence?: number;
}

function reverseBytes(buffer: Uint8Array): Uint8Array {
  if (buffer.length < 1) return buffer;
  const copy = Uint8Array.from(buffer);
  let j = copy.length - 1;
  let tmp = 0;
  for (let i = 0; i < copy.length / 2; i++) {
    tmp = copy[i]!;
    copy[i] = copy[j]!;
    copy[j] = tmp;
    j--;
  }
  return copy;
}

export function finalScriptsFuncFactory(
  scriptSatisfaction: Uint8Array,
  network: Network,
  paymentsOps: {
    p2wsh: BitcoinLib['payments']['p2wsh'];
    p2sh: BitcoinLib['payments']['p2sh'];
  }
): FinalScriptsFunc {
  const finalScriptsFunc: FinalScriptsFunc = (
    _index,
    _input,
    lockingScript /*witnessScript or redeemScript*/,
    isSegwit,
    isP2SH,
    _isP2WSH
  ) => {
    let finalScriptWitness: Uint8Array | undefined;
    let finalScriptSig: Uint8Array | undefined;
    //p2wsh
    if (isSegwit && !isP2SH) {
      const payment = paymentsOps.p2wsh({
        redeem: {
          input: scriptSatisfaction,
          output: lockingScript
        } as Payment,
        network
      });
      if (!payment.witness)
        throw new Error(`Error: p2wsh failed producing a witness`);
      finalScriptWitness = witnessStackToScriptWitness(payment.witness);
    }
    //p2sh-p2wsh
    else if (isSegwit && isP2SH) {
      const payment = paymentsOps.p2sh({
        redeem: paymentsOps.p2wsh({
          redeem: {
            input: scriptSatisfaction,
            output: lockingScript
          } as Payment,
          network
        }),
        network
      });
      if (!payment.witness)
        throw new Error(`Error: p2sh-p2wsh failed producing a witness`);
      finalScriptWitness = witnessStackToScriptWitness(payment.witness);
      finalScriptSig = payment.input;
    }
    //p2sh
    else {
      finalScriptSig = paymentsOps.p2sh({
        redeem: {
          input: scriptSatisfaction,
          output: lockingScript
        } as Payment,
        network
      }).input;
    }
    return {
      finalScriptWitness,
      finalScriptSig
    };
  };
  return finalScriptsFunc;
}

/**
 * Important: Read comments on Output.updatePsbtAsInput regarding not passing txHex
 */
export function addPsbtInput({
  psbt,
  vout,
  txHex,
  txId,
  value,
  sequence,
  locktime,
  keysInfo,
  scriptPubKey,
  isSegwit,
  tapInternalKey,
  tapLeafScript,
  tapBip32Derivation,
  witnessScript,
  redeemScript,
  rbf,
  TransactionOps
}: {
  psbt: PsbtLike;
  vout: number;
  txHex?: string;
  txId?: string;
  value?: bigint;
  sequence: number | undefined;
  locktime: number | undefined;
  keysInfo: KeyInfo[];
  scriptPubKey: Uint8Array;
  isSegwit: boolean;
  /** for taproot **/
  tapInternalKey?: Uint8Array | undefined;
  /** for taproot script-path **/
  tapLeafScript?: TapLeafScript[] | undefined;
  /** for taproot **/
  tapBip32Derivation?: TapBip32Derivation[] | undefined;
  witnessScript: Uint8Array | undefined;
  redeemScript: Uint8Array | undefined;
  rbf: boolean;
  TransactionOps: BitcoinLib['Transaction'];
}): number {
  if (value !== undefined && typeof value !== 'bigint')
    throw new Error(`Error: value must be a bigint`);
  if (value !== undefined && value < 0n)
    throw new Error(`Error: value must be >= 0n`);

  let normalizedValue = value;

  //Some data-sanity checks:
  if (sequence !== undefined && rbf && sequence > 0xfffffffd)
    throw new Error(`Error: incompatible sequence and rbf settings`);
  if (!isSegwit && txHex === undefined)
    throw new Error(`Error: txHex is mandatory for Non-Segwit inputs`);
  if (
    isSegwit &&
    txHex === undefined &&
    (txId === undefined || value === undefined)
  )
    throw new Error(`Error: pass txHex or txId+value for Segwit inputs`);
  if (txHex !== undefined) {
    const tx: ParsedTransaction = TransactionOps.fromHex(txHex);
    const out = tx.outs[vout];
    if (!out) throw new Error(`Error: tx ${txHex} does not have vout ${vout}`);
    const outputScript = out.script;
    if (!outputScript)
      throw new Error(
        `Error: could not extract outputScript for txHex ${txHex} and vout ${vout}`
      );
    if (compare(outputScript, scriptPubKey) !== 0)
      throw new Error(
        `Error: txHex ${txHex} for vout ${vout} does not correspond to scriptPubKey ${scriptPubKey}`
      );
    if (txId !== undefined) {
      if (tx.getId() !== txId)
        throw new Error(
          `Error: txId for ${txHex} and vout ${vout} does not correspond to ${txId}`
        );
    } else {
      txId = tx.getId();
    }
    if (normalizedValue !== undefined) {
      if (out.value !== normalizedValue)
        throw new Error(
          `Error: value for ${txHex} and vout ${vout} does not correspond to ${value}`
        );
    } else {
      normalizedValue = out.value;
    }
  }
  if (txId === undefined || normalizedValue === undefined)
    throw new Error(
      `Error: txHex+vout required. Alternatively, but ONLY for Segwit inputs, txId+value can also be passed.`
    );

  if (locktime) {
    if (psbt.locktime && psbt.locktime !== locktime)
      throw new Error(
        `Error: transaction locktime was already set with a different value: ${locktime} != ${psbt.locktime}`
      );
    // nLockTime only works if at least one of the transaction inputs has an
    // nSequence value that is below 0xffffffff. Let's make sure that at least
    // this input's sequence < 0xffffffff
    if (sequence === undefined) {
      //NOTE: if sequence is undefined, bitcoinjs-lib uses 0xffffffff as default
      sequence = rbf ? 0xfffffffd : 0xfffffffe;
    } else if (sequence > 0xfffffffe) {
      throw new Error(
        `Error: incompatible sequence: ${sequence} and locktime: ${locktime}`
      );
    }
    if (sequence === undefined && rbf) sequence = 0xfffffffd;
    psbt.setLocktime(locktime);
  } else {
    if (sequence === undefined) {
      if (rbf) sequence = 0xfffffffd;
      else sequence = 0xffffffff;
    }
  }

  const input: PsbtInputExtended = {
    hash: reverseBytes(fromHex(txId)),
    index: vout
  };
  if (txHex !== undefined) {
    input.nonWitnessUtxo = TransactionOps.fromHex(txHex).toBuffer();
  }

  if (tapInternalKey) {
    //Taproot
    const fallbackTapBip32Derivation = keysInfo
      .filter(
        (keyInfo: KeyInfo) =>
          keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
      )
      .map((keyInfo: KeyInfo): TapBip32Derivation => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey)
          throw new Error(`key ${keyInfo.keyExpression} missing pubkey`);
        return {
          masterFingerprint: keyInfo.masterFingerprint!,
          pubkey,
          path: keyInfo.path!,
          leafHashes: []
        };
      });

    const resolvedTapBip32Derivation =
      tapBip32Derivation || fallbackTapBip32Derivation;

    if (resolvedTapBip32Derivation.length)
      input.tapBip32Derivation = resolvedTapBip32Derivation;
    input.tapInternalKey = tapInternalKey;
    if (tapLeafScript && tapLeafScript.length > 0)
      input.tapLeafScript = tapLeafScript;
  } else {
    const bip32Derivation = keysInfo
      .filter(
        (keyInfo: KeyInfo) =>
          keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
      )
      .map((keyInfo: KeyInfo): Bip32Derivation => {
        const pubkey = keyInfo.pubkey;
        if (!pubkey)
          throw new Error(`key ${keyInfo.keyExpression} missing pubkey`);
        return {
          masterFingerprint: keyInfo.masterFingerprint!,
          pubkey,
          path: keyInfo.path!
        };
      });
    if (bip32Derivation.length) input.bip32Derivation = bip32Derivation;
  }
  if (isSegwit && txHex !== undefined) {
    //There's no need to put both witnessUtxo and nonWitnessUtxo
    input.witnessUtxo = { script: scriptPubKey, value: normalizedValue };
  }
  if (sequence !== undefined) input.sequence = sequence;

  if (witnessScript) input.witnessScript = witnessScript;
  if (redeemScript) input.redeemScript = redeemScript;

  psbt.addInput(input as unknown as Record<string, unknown>);
  return psbt.inputCount - 1;
}
