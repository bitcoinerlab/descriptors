export * from '@bitcoinerlab/descriptors-core';
export declare const btc: typeof import('@scure/btc-signer');
export declare const HDKey: typeof import('@scure/bip32').HDKey;
export declare const secp256k1: typeof import('@noble/curves/secp256k1.js').secp256k1;

type Bound = ReturnType<typeof import('@bitcoinerlab/descriptors-core').DescriptorsFactory>;

export declare const Output: Bound['Output'];
export declare const parseKeyExpression: Bound['parseKeyExpression'];
export declare const expand: Bound['expand'];
export declare const ECPair: Bound['ECPair'];
export declare const BIP32: Bound['BIP32'];
