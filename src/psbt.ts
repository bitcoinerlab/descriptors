import type { PsbtInput } from 'bip174/src/lib/interfaces';
import { payments, Network } from 'bitcoinjs-lib';
import * as varuint from 'bip174/src/lib/converter/varint';

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
