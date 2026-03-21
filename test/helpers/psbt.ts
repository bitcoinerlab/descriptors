// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/**
 * PSBT helper functions for test abstraction across bitcoinjs-lib and @scure/btc-signer
 *
 * These helpers allow tests to work with both backends using concrete types.
 */

import { Psbt } from 'bitcoinjs-lib';
import * as btc from '@scure/btc-signer';
import { base64 } from '@scure/base';
import type { Network } from '../../dist/networks';

// ─── Type Guards ─────────────────────────────────────────────────────

export function isScurePsbt(
  psbt: Psbt | btc.Transaction
): psbt is btc.Transaction {
  return 'inputsLength' in psbt && 'toPSBT' in psbt;
}

// ─── Tier 1: Count & Existence ────────────────────────────────────────

export function getPsbtInputCount(psbt: Psbt | btc.Transaction): number {
  if (isScurePsbt(psbt)) {
    return psbt.inputsLength;
  }
  return psbt.inputCount;
}

export function getPsbtOutputCount(psbt: Psbt | btc.Transaction): number {
  if (isScurePsbt(psbt)) {
    return psbt.outputsLength;
  }
  return psbt.data.outputs?.length ?? 0;
}

export function hasPsbtInput(
  psbt: Psbt | btc.Transaction,
  index: number
): boolean {
  return index >= 0 && index < getPsbtInputCount(psbt);
}

export function hasPsbtOutput(
  psbt: Psbt | btc.Transaction,
  index: number
): boolean {
  return index >= 0 && index < getPsbtOutputCount(psbt);
}

// ─── Tier 2: Timelock ─────────────────────────────────────────────────

export function getPsbtInputSequence(
  psbt: Psbt | btc.Transaction,
  index: number
): number | undefined {
  if (!hasPsbtInput(psbt, index)) {
    return undefined;
  }

  if (isScurePsbt(psbt)) {
    const input = psbt.getInput(index);
    return input.sequence;
  }

  return psbt.txInputs[index]?.sequence;
}

export function getPsbtLocktime(psbt: Psbt | btc.Transaction): number {
  if (isScurePsbt(psbt)) {
    return psbt.lockTime;
  }
  return psbt.locktime;
}

// ─── Tier 3: Transaction Serialization ───────────────────────────────

export function psbtToHex(psbt: Psbt | btc.Transaction): string {
  if (isScurePsbt(psbt)) {
    return psbt.hex;
  }
  return psbt.extractTransaction().toHex();
}

export function psbtToTxId(psbt: Psbt | btc.Transaction): string {
  if (isScurePsbt(psbt)) {
    return psbt.id;
  }
  return psbt.extractTransaction().getId();
}

// ─── Tier 4: Modification ─────────────────────────────────────────────

export function psbtAddOutput(
  psbt: Psbt | btc.Transaction,
  output: { script?: Uint8Array; address?: string; value: bigint },
  network?: Network
): void {
  if (isScurePsbt(psbt)) {
    // Scure Transaction uses amount instead of value
    // It has separate methods: addOutput (for script) and addOutputAddress (for address)
    if (output.address) {
      if (!network) {
        throw new Error(
          'network parameter is required when using address with @scure/btc-signer backend'
        );
      }
      psbt.addOutputAddress(output.address, output.value, network);
    } else if (output.script) {
      psbt.addOutput({ script: output.script, amount: output.value });
    } else {
      throw new Error('Either script or address must be provided');
    }
  } else {
    // bitcoinjs-lib accepts both script and address in addOutput
    // Need to cast since TypeScript doesn't know which overload to use
    psbt.addOutput(
      output as
        | { script: Uint8Array; value: bigint }
        | { address: string; value: bigint }
    );
  }
}

// ─── Tier 5: Serialization to Base64 ──────────────────────────────────

export function psbtToBase64(psbt: Psbt | btc.Transaction): string {
  if (isScurePsbt(psbt)) {
    // Scure Transaction has toPSBT() method that returns bytes
    const psbtBytes = psbt.toPSBT();
    return base64.encode(psbtBytes);
  }
  // bitcoinjs-lib has native toBase64() method
  return psbt.toBase64();
}

// ─── Tier 6: Loading from Fixtures ───────────────────────────────────

export function psbtFromBase64(
  base64String: string,
  isScure: boolean = false
): Psbt | btc.Transaction {
  if (isScure) {
    // This is scure - parse PSBT bytes
    const bytes = base64.decode(base64String);
    return btc.Transaction.fromPSBT(bytes);
  }

  // This is bitcoinjs-lib
  return Psbt.fromBase64(base64String);
}

// ─── PSBT Creation ──────────────────────────────────────────────────

export function createPsbt(
  isScure: boolean = false,
  network?: Network
): Psbt | btc.Transaction {
  if (isScure) {
    // Create scure Transaction
    return new btc.Transaction();
  }

  // Create bitcoinjs-lib Psbt
  return network ? new Psbt({ network }) : new Psbt();
}
