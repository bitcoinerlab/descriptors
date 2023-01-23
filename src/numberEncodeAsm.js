// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { script } from 'bitcoinjs-lib';
/**
 *
 * Use this function instead of bitcoinjs-lib's equivalent `script.number.encode`
 * when encoding numbers to be compiled with `fromASM` to avoid problems.
 *
 * Motivation:
 *
 * Numbers in Bitcoin assembly code are represented in hex and in Little Endian.
 * Decimal: 32766 - Big endian: 0x7FFE - Little Endian: 0xFE7F.
 *
 * This function takes an integer and encodes it so that bitcoinjs-lib `fromASM`
 * can compile it. This is basically what bitcoinjs-lib's `script.number.encode`
 * does.
 *
 * Note that `fromASM` already converts integers from 1 to 16 to
 * OP_1 ... OP_16 {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/59b21162a2c4645c64271ca004c7a3755a3d72fb/src/script.js#L33 here}.
 * This is done in Bitcoin to save some bits.
 *
 * Neither this function nor `script.number.encode` convert numbers to
 * their op code equivalent since this is done later in `fromASM`.
 *
 * Both functions simply convert numbers to Little Endian.
 *
 * However, the `0` number is an edge case that we specially handle with this
 * function.
 *
 * bitcoinjs-lib's `bscript.number.encode(0)` produces an empty Buffer.
 * This is what the Bitcoin interpreter does and it is what `script.number.encode` was
 * implemented to do.
 *
 * The problem is `bscript.number.encode(0).toString('hex')` produces an
 * empty string and thus it should not be used to serialize number zero before `fromASM`.
 *
 * A zero should produce the OP_0 ASM symbolic code (corresponding to a `0` when
 * compiled).
 *
 * So, this function will produce a string in hex format in Little Endian
 * encoding for integers not equal to `0` and it will return `OP_0` for `0`.
 *
 * Read more about the this {@link https://github.com/bitcoinjs/bitcoinjs-lib/issues/1799#issuecomment-1122591738 here}.
 *
 * Use it in combination with `fromASM` like this:
 *
 * ```javascript
 * //To produce "0 1 OP_ADD":
 * fromASM(
 * `${numberEncodeAsm(0)} ${numberEncodeAsm(1)} OP_ADD`
 *   .trim().replace(/\s+/g, ' ')
 * )
 * ```
 *
 * @param {number} number An integer.
 * @returns {string} Returns `"OP_0"` for `number === 0` and a hex string representing other numbers in Little Endian encoding.
 */
export function numberEncodeAsm(number) {
  if (Number.isSafeInteger(number) === false) {
    throw new Error(`Error: invalid number ${number}`);
  }
  if (number === 0) {
    return 'OP_0';
  } else return script.number.encode(number).toString('hex');
}
