/* eslint-disable @typescript-eslint/no-require-imports */
/*
 * bitcoinjs-lib v7 does not export all the taproot/psbt helpers we need from
 * its top-level API, so this module centralizes only the required deep imports.
 */

import type * as Bip341 from 'bitcoinjs-lib/src/cjs/payments/bip341';
import type * as Bip371 from 'bitcoinjs-lib/src/cjs/psbt/bip371';
import type * as PsbtUtils from 'bitcoinjs-lib/src/cjs/psbt/psbtutils';

const bip341 = require('bitcoinjs-lib/src/payments/bip341') as typeof Bip341;
const bip371 = require('bitcoinjs-lib/src/psbt/bip371') as typeof Bip371;
const psbtUtils =
  require('bitcoinjs-lib/src/psbt/psbtutils') as typeof PsbtUtils;

export const findScriptPath = bip341.findScriptPath;
export const tapleafHash = bip341.tapleafHash;
export const tapTweakHash = bip341.tapTweakHash;
export const toHashTree = bip341.toHashTree;
export const tweakKey = bip341.tweakKey;

export const witnessStackToScriptWitness =
  psbtUtils.witnessStackToScriptWitness;
export const isTaprootInput = bip371.isTaprootInput;
