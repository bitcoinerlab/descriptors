/*
 * Reimplements a small subset of bitcoinjs-lib internal helpers.
 * Keep this module free of deep imports (for example `bitcoinjs-lib/src/*`)
 * so it works consistently across Node.js, browser bundlers (including
 * CodeSandbox), and React Native/Metro.
 */

import type { PsbtInput } from 'bip174';
import { encode } from 'varuint-bitcoin';
import { concat } from 'uint8array-tools';

const TAPROOT_LEAF_VERSION_TAPSCRIPT = 0xc0;
const OP_1 = 0x51;
const PUSH_DATA_32 = 0x20;

type Tapleaf = {
  output: Uint8Array;
  version?: number;
};

function serializeScript(script: Uint8Array): Uint8Array {
  const { buffer: encodedLength } = encode(script.length);
  return concat([encodedLength, script]);
}

function isP2TRScript(script: Uint8Array | undefined): boolean {
  return (
    script instanceof Uint8Array &&
    script.length === 34 &&
    script[0] === OP_1 &&
    script[1] === PUSH_DATA_32
  );
}

export function tapleafHash(
  leaf: Tapleaf,
  taggedHash: (tag: string, data: Uint8Array) => Uint8Array
): Uint8Array {
  const version = leaf.version || TAPROOT_LEAF_VERSION_TAPSCRIPT;
  return taggedHash(
    'TapLeaf',
    concat([Uint8Array.from([version]), serializeScript(leaf.output)])
  );
}

export function tapTweakHash(
  pubKey: Uint8Array,
  h: Uint8Array | undefined,
  taggedHash: (tag: string, data: Uint8Array) => Uint8Array
): Uint8Array {
  return taggedHash('TapTweak', concat(h ? [pubKey, h] : [pubKey]));
}

export function witnessStackToScriptWitness(witness: Uint8Array[]): Uint8Array {
  let buffer: Uint8Array = new Uint8Array(0);

  const writeSlice = (slice: Uint8Array) => {
    buffer = concat([buffer, slice]);
  };

  const writeVarInt = (value: number) => {
    const { buffer: encoded } = encode(value);
    writeSlice(encoded);
  };

  const writeVarSlice = (slice: Uint8Array) => {
    writeVarInt(slice.length);
    writeSlice(slice);
  };

  writeVarInt(witness.length);
  witness.forEach(writeVarSlice);
  return buffer;
}

export function isTaprootInput(input: PsbtInput | undefined): boolean {
  return (
    !!input &&
    !!(
      input.tapInternalKey ||
      input.tapMerkleRoot ||
      (input.tapLeafScript && input.tapLeafScript.length > 0) ||
      (input.tapBip32Derivation && input.tapBip32Derivation.length > 0) ||
      isP2TRScript(input.witnessUtxo?.script)
    )
  );
}
