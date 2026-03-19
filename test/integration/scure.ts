// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// npm run test:integration:scure

console.log('Scure integration test: legacy to segwit');

import * as ecc from '@bitcoinerlab/secp256k1';
import { mnemonicToSeedSync } from 'bip39';
import { RegtestUtils } from 'regtest-client';

import { toPsbt } from '../../dist/psbt';
import {
  DescriptorsFactory,
  networks,
  scriptExpressions,
  signers
} from '../../dist/';
import { createScureLib } from '../../dist/scure';
import * as btc from '@scure/btc-signer';
import type { ScureTransactionLike } from '../../dist/';

const { pkhBIP32, wpkhBIP32 } = scriptExpressions;
const { signBIP32 } = signers;

const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const INITIAL_VALUE = 30_000n;
const FEE = 500n;

// This mnemonic mirrors the playground example so users can recognize the flow
// immediately, while the test itself still uses the local regtest faucet.
const MNEMONIC =
  'drum turtle globe inherit autumn flavor ' +
  'slice illness sniff distance carbon elder';

const scureLib = createScureLib(ecc);
const { Output, BIP32 } = DescriptorsFactory(scureLib);

const masterNode = BIP32.fromSeed(mnemonicToSeedSync(MNEMONIC), NETWORK);

// Start with a legacy descriptor and move the funds to a segwit one, matching
// the educational playground flow but using the native scure-backed `Psbt`.
const legacyOutput = new Output({
  descriptor: pkhBIP32({
    masterNode,
    network: NETWORK,
    account: 0,
    keyPath: '/0/1'
  }),
  network: NETWORK
});

const segwitOutput = new Output({
  descriptor: wpkhBIP32({
    masterNode,
    network: NETWORK,
    account: 0,
    keyPath: '/1/0'
  }),
  network: NETWORK
});

(async () => {
  const { txId, vout } = await regtestUtils.faucetComplex(
    Buffer.from(legacyOutput.getScriptPubKey()),
    Number(INITIAL_VALUE)
  );
  const { txHex } = await regtestUtils.fetch(txId);

  // Scure users construct a Transaction directly from @scure/btc-signer.
  // The library converts it internally via toPsbt().
  const psbt: ScureTransactionLike = new btc.Transaction({
    allowUnknownOutputs: true,
    disableScriptCheck: true
  }) as ScureTransactionLike;

  const finalizeLegacyInput = legacyOutput.updatePsbtAsInput({
    psbt,
    txHex,
    vout
  });

  const finalValue = INITIAL_VALUE - FEE;
  segwitOutput.updatePsbtAsOutput({ psbt, value: finalValue });

  // Convert scure Transaction to BitcoinjsPsbtLike interface for signing.
  // This wraps the native scure transaction so it can be used with library signing functions.
  const wrappedPsbt = toPsbt(psbt);
  signBIP32({ psbt: wrappedPsbt, masterNode });
  finalizeLegacyInput({ psbt: wrappedPsbt });

  // Access the native @scure/btc-signer transaction methods directly.
  // The psbt has been converted and finalized internally.
  const finalAddress = segwitOutput.getAddress();
  if (!finalAddress) throw new Error('Error: final segwit address not found');

  // Cast to btc.Transaction type to access native scure properties
  const scureTx = psbt as unknown as btc.Transaction;
  await regtestUtils.broadcast(scureTx.hex);
  await regtestUtils.verify({
    txId: scureTx.id,
    address: finalAddress,
    vout: 0,
    value: Number(finalValue)
  });

  console.log('Scure integration test: OK');
})();
