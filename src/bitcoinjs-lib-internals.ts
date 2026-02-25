/*
 * bitcoinjs-lib v7 does not export all the taproot/psbt helpers we need from
 * its top-level API, so this module centralizes only the required deep imports.
 *
 * The subpath specifiers (bitcoinjs-lib/src/...) resolve at runtime via the
 * package's "exports" map.  TypeScript type information is provided by the
 * ambient declarations in ./bitcoinjs-lib-subpaths.d.ts.
 */

export {
  findScriptPath,
  tapleafHash,
  tapTweakHash,
  toHashTree,
  tweakKey
} from 'bitcoinjs-lib/src/payments/bip341';

export { isTaprootInput } from 'bitcoinjs-lib/src/psbt/bip371';

export { witnessStackToScriptWitness } from 'bitcoinjs-lib/src/psbt/psbtutils';
