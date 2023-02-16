// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { PsbtInput, Bip32Derivation } from 'bip174/src/lib/interfaces';
import type { KeyInfo } from './types';
import {
  payments,
  Network,
  Psbt,
  Transaction,
  PsbtTxInput
} from 'bitcoinjs-lib';
import * as varuint from 'bip174/src/lib/converter/varint';
interface PsbtInputExtended extends PsbtInput, PsbtTxInput {}

function witnessStackToScriptWitness(witness: Buffer[]): Buffer {
  let buffer = Buffer.allocUnsafe(0);

  function writeSlice(slice: Buffer): void {
    buffer = Buffer.concat([buffer, Buffer.from(slice)]);
  }

  function writeVarInt(i: number): void {
    const currentLen = buffer.length;
    const varintLen = varuint.encodingLength(i);

    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
    varuint.encode(i, buffer, currentLen);
  }

  function writeVarSlice(slice: Buffer): void {
    writeVarInt(slice.length);
    writeSlice(slice);
  }

  function writeVector(vector: Buffer[]): void {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }

  writeVector(witness);

  return buffer;
}

/**
 * This function must do two things:
 * 1. Check if the `input` can be finalized. If it can not be finalized, throw.
 *   ie. `Can not finalize input #${inputIndex}`
 * 2. Create the finalScriptSig and finalScriptWitness Buffers.
 */
export type FinalScriptsFunc = (
  inputIndex: number, // Which input is it?
  input: PsbtInput, // The PSBT input contents
  script: Buffer, // The "meaningful" locking script Buffer (redeemScript for P2SH etc.)
  isSegwit: boolean, // Is it segwit?
  isP2SH: boolean, // Is it P2SH?
  isP2WSH: boolean // Is it P2WSH?
) => {
  finalScriptSig: Buffer | undefined;
  finalScriptWitness: Buffer | undefined;
};

export function finalScriptsFuncFactory(
  scriptSatisfaction: Buffer,
  network: Network
): FinalScriptsFunc {
  const finalScriptsFunc: FinalScriptsFunc = (
    _index,
    _input,
    lockingScript /*witnessScript or redeemScript*/,
    isSegwit,
    isP2SH,
    _isP2WSH
  ) => {
    let finalScriptWitness: Buffer | undefined;
    let finalScriptSig: Buffer | undefined;
    //p2wsh
    if (isSegwit && !isP2SH) {
      const payment = payments.p2wsh({
        redeem: { input: scriptSatisfaction, output: lockingScript },
        network
      });
      if (!payment.witness)
        throw new Error(`Error: p2wsh failed producing a witness`);
      finalScriptWitness = witnessStackToScriptWitness(payment.witness);
    }
    //p2sh-p2wsh
    else if (isSegwit && isP2SH) {
      const payment = payments.p2sh({
        redeem: payments.p2wsh({
          redeem: { input: scriptSatisfaction, output: lockingScript },
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
      finalScriptSig = payments.p2sh({
        redeem: { input: scriptSatisfaction, output: lockingScript },
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

export function updatePsbt({
  psbt,
  txHex,
  vout,
  sequence,
  locktime,
  keysInfo,
  scriptPubKey,
  isSegwit,
  witnessScript,
  redeemScript
}: {
  psbt: Psbt;
  txHex: string;
  vout: number;
  sequence: number | undefined;
  locktime: number | undefined;
  keysInfo: KeyInfo[];
  scriptPubKey: Buffer;
  isSegwit: boolean;
  witnessScript: Buffer | undefined;
  redeemScript: Buffer | undefined;
}): number {
  const tx = Transaction.fromHex(txHex);
  const out = tx?.outs?.[vout];
  const outputScript = out?.script;
  if (!outputScript)
    throw new Error(
      `Error: could not extract outputScript for txHex ${txHex} and vout ${vout}`
    );
  if (Buffer.compare(outputScript, scriptPubKey) !== 0)
    throw new Error(
      `Error: txHex ${txHex} for vout ${vout} does not correspond to scriptPubKey ${scriptPubKey}`
    );
  if (!out) throw new Error(`Error: tx ${txHex} does not have vout ${vout}`);
  if (locktime !== undefined) {
    if (psbt.locktime !== 0 && psbt.locktime !== undefined)
      throw new Error(
        `Error: transaction locktime has already been set: ${psbt.locktime}`
      );
    psbt.setLocktime(locktime);
  }
  let inputSequence;
  if (locktime !== undefined) {
    if (sequence === undefined) {
      // for CTV nSequence MUST be <= 0xfffffffe otherwise OP_CHECKLOCKTIMEVERIFY will fail.
      inputSequence = 0xfffffffe;
    } else if (sequence > 0xfffffffe) {
      throw new Error(
        `Error: incompatible sequence: ${inputSequence} and locktime: ${locktime}`
      );
    } else {
      inputSequence = sequence;
    }
  } else {
    inputSequence = sequence;
  }

  const input: PsbtInputExtended = {
    hash: tx.getHash(),
    index: vout,
    nonWitnessUtxo: tx.toBuffer()
  };
  const bip32Derivation = keysInfo
    .filter(
      (keyInfo: KeyInfo) =>
        keyInfo.pubkey && keyInfo.masterFingerprint && keyInfo.path
    )
    .map(
      (keyInfo: KeyInfo): Bip32Derivation => ({
        masterFingerprint: keyInfo.masterFingerprint!,
        pubkey: keyInfo.pubkey,
        path: keyInfo.path!
      })
    );
  if (bip32Derivation.length) input.bip32Derivation = bip32Derivation;
  if (isSegwit) input.witnessUtxo = { script: scriptPubKey, value: out.value };
  if (inputSequence !== undefined) input.sequence = inputSequence;

  if (witnessScript) input.witnessScript = witnessScript;
  if (redeemScript) input.redeemScript = redeemScript;

  psbt.addInput(input);
  return psbt.data.inputs.length - 1;
}
