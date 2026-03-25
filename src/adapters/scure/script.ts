// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import type { ScriptType } from '@scure/btc-signer/script.js';

type ScriptElement = ScriptType[number];

const SIGNER_OP_NAMES = new Set<string>();
for (const key of Object.keys(btc.OP))
  if (isNaN(Number(key))) SIGNER_OP_NAMES.add(key);

function isPushOnlyChunk(chunk: number | Uint8Array) {
  if (chunk instanceof Uint8Array) return true;
  return (
    chunk === btc.OP.OP_0 ||
    chunk === btc.OP['1NEGATE'] ||
    (chunk >= btc.OP.OP_1 && chunk <= btc.OP.OP_16)
  );
}

function asmTokenToSignerOp(token: string) {
  if (token === 'OP_0' || token === 'OP_FALSE') return 'OP_0';
  if (token === 'OP_1' || token === 'OP_TRUE') return 'OP_1';
  for (let i = 2; i <= 16; i++)
    if (token === `OP_${i}`) return `OP_${i}` as ScriptElement;

  if (token === '1NEGATE' || token === 'OP_1NEGATE') return '1NEGATE';

  if (token.startsWith('OP_')) {
    const stripped = token.slice(3);
    if (SIGNER_OP_NAMES.has(stripped)) return stripped as ScriptElement;
  }
  if (SIGNER_OP_NAMES.has(token)) return token as ScriptElement;

  return undefined;
}

/** Convert ASM string to script bytes. */
export function fromASM(asm: string) {
  const trimmed = asm.trim();
  if (trimmed === '') throw new Error('Invalid ASM string');
  const tokens = trimmed.split(/\s+/);
  const scriptElements: ScriptType = [];

  for (const token of tokens) {
    if (token === '') continue;
    const op = asmTokenToSignerOp(token);
    if (op !== undefined) {
      scriptElements.push(op);
    } else {
      const data = hex.decode(token);
      if (data.length === 0) scriptElements.push('OP_0');
      else if (data.length === 1 && data[0]! >= 1 && data[0]! <= 16)
        scriptElements.push(`OP_${data[0]!}` as keyof typeof btc.OP);
      else if (data.length === 1 && data[0] === 0x81)
        scriptElements.push('1NEGATE');
      else scriptElements.push(data);
    }
  }

  return btc.Script.encode(scriptElements);
}

/** Decompile script to array of opcodes (numbers) and data (Uint8Array). */
export function decompile(script: Uint8Array) {
  try {
    const decoded = btc.Script.decode(script);
    return decoded.map(item => {
      if (typeof item === 'number') {
        if (item === 0) return btc.OP.OP_0;
        if (item >= 1 && item <= 16) return btc.OP.RESERVED + item;
        return item;
      }
      if (item instanceof Uint8Array) return item;
      const opNum = btc.OP[item];
      if (opNum !== undefined) return opNum;
      throw new Error('Unknown script token');
    });
  } catch {
    return null;
  }
}

/** Count non-push-only opcodes in a script. */
export function countNonPushOnlyOPs(chunks: Array<number | Uint8Array>) {
  return chunks.length - chunks.filter(isPushOnlyChunk).length;
}

/** Decompile a script into its push-data items. */
export function toStack(scriptBuf: Uint8Array) {
  const chunks = decompile(scriptBuf);
  if (!chunks) throw new Error('Could not decompile script');
  if (!chunks.every(isPushOnlyChunk)) throw new Error('Non push-only script');

  return chunks.map(chunk => {
    if (typeof chunk === 'number') {
      if (chunk === btc.OP.OP_0) return new Uint8Array(0);
      return numberEncode(chunk - btc.OP.RESERVED);
    }
    return chunk;
  });
}

/** Encode a number for use in Bitcoin Script (CScriptNum format). */
function numberEncode(n: number) {
  if (!Number.isSafeInteger(n))
    throw new Error(`Error: invalid script number ${n}`);
  return btc.ScriptNum().encode(BigInt(n));
}

export function createScureScriptAdapter() {
  return {
    fromASM,
    toStack,
    decompile,
    countNonPushOnlyOPs,
    number: {
      encode: numberEncode
    }
  };
}
