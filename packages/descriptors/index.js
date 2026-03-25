'use strict';

const core = require('@bitcoinerlab/descriptors-core');
const { createBitcoinjsLib } = require('@bitcoinerlab/descriptors-core/bitcoinjs');
const ecc = require('@bitcoinerlab/secp256k1');
const { Psbt } = require('bitcoinjs-lib');

const bound = core.DescriptorsFactory(ecc);

exports.networks = core.networks;
exports.DescriptorsFactory = core.DescriptorsFactory;
exports.checksum = core.checksum;
exports.signers = core.signers;
exports.keyExpressionBIP32 = core.keyExpressionBIP32;
exports.keyExpressionLedger = core.keyExpressionLedger;
exports.scriptExpressions = core.scriptExpressions;
exports.ledger = core.ledger;

exports.Output = bound.Output;
exports.parseKeyExpression = bound.parseKeyExpression;
exports.expand = bound.expand;
exports.ECPair = bound.ECPair;
exports.BIP32 = bound.BIP32;

exports.ecc = ecc;
exports.Psbt = Psbt;
exports.createBitcoinjsLib = createBitcoinjsLib;
