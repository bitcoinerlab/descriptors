/*
 * bitcoinjs-lib v7 uses a package "exports" map that routes
 * `bitcoinjs-lib/src/*` to the correct CJS/ESM files at runtime.
 * TypeScript's Node10 module resolution does not read "exports",
 * so we declare the subpath modules here, forwarding their types
 * from the CJS declarations that TypeScript CAN resolve.
 */

declare module 'bitcoinjs-lib/src/payments/bip341' {
  export * from 'bitcoinjs-lib/src/cjs/payments/bip341';
}

declare module 'bitcoinjs-lib/src/psbt/bip371' {
  export * from 'bitcoinjs-lib/src/cjs/psbt/bip371';
}

declare module 'bitcoinjs-lib/src/psbt/psbtutils' {
  export * from 'bitcoinjs-lib/src/cjs/psbt/psbtutils';
}
