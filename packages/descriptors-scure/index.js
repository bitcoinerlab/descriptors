'use strict';

const core = require('@bitcoinerlab/descriptors-core');
const { createScureLib } = require('@bitcoinerlab/descriptors-core/scure');
const btc = require('@scure/btc-signer');
const { HDKey } = require('@scure/bip32');
const { secp256k1 } = require('@noble/curves/secp256k1.js');

const bound = core.DescriptorsFactory(createScureLib());

module.exports = {
  ...core,
  ...bound,
  btc,
  HDKey,
  secp256k1
};
