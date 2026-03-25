export * from '@bitcoinerlab/descriptors-core';
export { createBitcoinjsLib } from '@bitcoinerlab/descriptors-core/bitcoinjs';

export declare const ecc: typeof import('@bitcoinerlab/secp256k1');
export declare const Psbt: typeof import('bitcoinjs-lib').Psbt;

type Bound = ReturnType<typeof import('@bitcoinerlab/descriptors-core').DescriptorsFactory>;

export declare const Output: Bound['Output'];
export declare const parseKeyExpression: Bound['parseKeyExpression'];
export declare const expand: Bound['expand'];
export declare const ECPair: Bound['ECPair'];
export declare const BIP32: Bound['BIP32'];
