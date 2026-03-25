'use strict';

const core = require('@bitcoinerlab/descriptors-core');
const { createScureLib } = require('@bitcoinerlab/descriptors-core/scure');
const btc = require('@scure/btc-signer');
const { HDKey } = require('@scure/bip32');
const { secp256k1 } = require('@noble/curves/secp256k1.js');

const bound = core.DescriptorsFactory(createScureLib());

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

exports.btc = btc;
exports.HDKey = HDKey;
exports.secp256k1 = secp256k1;
