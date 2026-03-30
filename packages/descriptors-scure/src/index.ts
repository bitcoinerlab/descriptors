import * as core from '@bitcoinerlab/descriptors-core';
import { createScureLib } from '@bitcoinerlab/descriptors-core/scure';
import * as btc from '@scure/btc-signer';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';

export type {
  Expansion,
  ExpansionMap,
  KeyExpressionParser,
  KeyInfo,
  Preimage,
  TimeConstraints,
  TreeNode,
  TapTreeNode,
  TapTreeInfoNode,
  TapLeaf,
  TapLeafInfo,
  OutputInstance,
  OutputConstructor,
  Network
} from '@bitcoinerlab/descriptors-core';
export {
  networks,
  checksum,
  signers,
  keyExpressionBIP32,
  scriptExpressions
} from '@bitcoinerlab/descriptors-core';
export { btc, HDKey, secp256k1 };

const bound = core.DescriptorsFactory(createScureLib());
export const { Output, parseKeyExpression, expand } = bound;
