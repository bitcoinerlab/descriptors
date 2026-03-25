'use strict';

const core = require('@bitcoinerlab/descriptors-core');
const { createBitcoinjsLib } = require('@bitcoinerlab/descriptors-core/bitcoinjs');
const ecc = require('@bitcoinerlab/secp256k1');
const { Psbt } = require('bitcoinjs-lib');

const bound = core.DescriptorsFactory(ecc);

module.exports = {
  ...core,
  ...bound,
  ecc,
  Psbt,
  createBitcoinjsLib
};
