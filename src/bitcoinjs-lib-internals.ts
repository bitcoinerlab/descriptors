/* eslint-disable @typescript-eslint/no-require-imports */
/*
 * bitcoinjs-lib v7 does not export all the taproot/psbt helpers we need from
 * its top-level API, so this module centralizes only the required deep imports.
 */

import type * as Bip341 from 'bitcoinjs-lib/src/cjs/payments/bip341';
import type * as Bip371 from 'bitcoinjs-lib/src/cjs/psbt/bip371';
import type * as PsbtUtils from 'bitcoinjs-lib/src/cjs/psbt/psbtutils';

function resolveAbsoluteCjsPath(relativePath: string): string | undefined {
  try {
    const entryPoint = require.resolve('bitcoinjs-lib');
    const root = entryPoint.replace(/src[\\/]+cjs[\\/]+index\.cjs$/, '');
    if (root === entryPoint) return undefined;
    return `${root}src/cjs/${relativePath}.cjs`;
  } catch (_err) {
    void _err;
    return undefined;
  }
}

function requireBitcoinJsInternal<T>(relativePath: string): T {
  const candidatePaths = [
    `bitcoinjs-lib/src/${relativePath}`,
    `bitcoinjs-lib/src/cjs/${relativePath}.cjs`
  ];
  const absoluteCjsPath = resolveAbsoluteCjsPath(relativePath);
  if (absoluteCjsPath) candidatePaths.push(absoluteCjsPath);

  let lastError: unknown;
  for (const modulePath of candidatePaths) {
    try {
      return require(modulePath) as T;
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

const bip341 = requireBitcoinJsInternal<typeof Bip341>('payments/bip341');
const bip371 = requireBitcoinJsInternal<typeof Bip371>('psbt/bip371');
const psbtUtils = requireBitcoinJsInternal<typeof PsbtUtils>('psbt/psbtutils');

export const findScriptPath = bip341.findScriptPath;
export const tapleafHash = bip341.tapleafHash;
export const tapTweakHash = bip341.tapTweakHash;
export const toHashTree = bip341.toHashTree;
export const tweakKey = bip341.tweakKey;

export const witnessStackToScriptWitness =
  psbtUtils.witnessStackToScriptWitness;
export const isTaprootInput = bip371.isTaprootInput;
