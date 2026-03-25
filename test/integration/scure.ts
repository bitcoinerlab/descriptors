// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// npm run test:integration:scure

console.log('Scure integration test: legacy to segwit');

import * as ecc from '@bitcoinerlab/secp256k1';
import { mnemonicToSeedSync } from 'bip39';
import { RegtestUtils } from 'regtest-client';

import {
  DescriptorsFactory,
  networks,
  scriptExpressions,
  signers
} from '../../dist/';
import { createScureLib } from '../../dist/scure';

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

  // Scure users construct the PSBT-compatible wrapper from the backend lib
  // itself, not from `DescriptorsFactory`.
  const psbt = new scureLib.Psbt();

  const finalizeLegacyInput = legacyOutput.updatePsbtAsInput({
    psbt,
    txHex,
    vout
  });

  const finalValue = INITIAL_VALUE - FEE;
  segwitOutput.updatePsbtAsOutput({ psbt, value: finalValue });

  signBIP32({ psbt, masterNode });
  finalizeLegacyInput({ psbt });

  // `raw` exposes the native @scure/btc-signer transaction. We use its native
  // `hex`/`id` helpers directly so this test documents the intended scure flow.
  const spendTx = psbt.raw;
  const finalAddress = segwitOutput.getAddress();
  if (!finalAddress) throw new Error('Error: final segwit address not found');

  await regtestUtils.broadcast(spendTx.hex);
  await regtestUtils.verify({
    txId: spendTx.id,
    address: finalAddress,
    vout: 0,
    value: Number(finalValue)
  });

  console.log('Scure integration test: OK');
})();
