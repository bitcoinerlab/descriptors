// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// npm run test:integration:scure

console.log('Scure integration test: legacy to segwit');

// This test uses the native @scure/btc-signer Transaction object.
// Exit early if running with bitcoinjs-lib backend (or no backend specified).
if (process.env['BITCOIN_LIB'] && process.env['BITCOIN_LIB'] !== 'scure') {
  console.log('SKIP: This test requires scure backend');
  process.exit(0);
}

import * as ecc from '@bitcoinerlab/secp256k1';
import { mnemonicToSeedSync } from '@scure/bip39';
import { RegtestUtils } from 'regtest-client';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { toHex } from 'uint8array-tools';

import {
  DescriptorsFactory,
  networks,
  scriptExpressions,
  signers
} from '../../dist/';
import { createScureLib } from '../../dist/scure';
import * as btc from '@scure/btc-signer';

const { pkhBIP32, wpkhBIP32 } = scriptExpressions;
const { signBIP32, signPrivKey, signInputPrivKey } = signers;

const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const INITIAL_VALUE = 30_000n;
const FEE = 500n;

const MNEMONIC =
  'drum turtle globe inherit autumn flavor ' +
  'slice illness sniff distance carbon elder';

const { Output } = DescriptorsFactory(createScureLib(ecc));

const masterNode = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC), {
  public: NETWORK.bip32.public,
  private: NETWORK.bip32.private
});

(async () => {
  const singleInputFinalValue = INITIAL_VALUE - FEE;
  const twoInputFinalValue = INITIAL_VALUE * 2n - FEE;
  const segwitOutput = new Output({
    descriptor: wpkhBIP32({
      masterNode,
      network: NETWORK,
      account: 0,
      keyPath: '/1/0'
    }),
    network: NETWORK
  });
  const finalAddress = segwitOutput.getAddress();
  if (!finalAddress) throw new Error('Error: final segwit address not found');

  // 1) BIP32 signer flow
  {
    const legacyOutput = new Output({
      descriptor: pkhBIP32({
        masterNode,
        network: NETWORK,
        account: 0,
        keyPath: '/0/1'
      }),
      network: NETWORK
    });
    const { txId, vout } = await regtestUtils.faucetComplex(
      Buffer.from(legacyOutput.getScriptPubKey()),
      Number(INITIAL_VALUE)
    );
    const { txHex } = await regtestUtils.fetch(txId);

    const psbt = new btc.Transaction();
    const finalizeInput = legacyOutput.updatePsbtAsInput({ psbt, txHex, vout });
    segwitOutput.updatePsbtAsOutput({ psbt, value: singleInputFinalValue });

    signBIP32({ psbt, masterNode });
    finalizeInput({ psbt });

    await regtestUtils.broadcast(psbt.hex);
    await regtestUtils.verify({
      txId: psbt.id,
      address: finalAddress,
      vout: 0,
      value: Number(singleInputFinalValue)
    });
  }

  // Also demonstrate the raw-private-key signers for scure-only users.
  const singlePrivKey = btc.utils.randomPrivateKeyBytes();
  const singlePubKeyHex = toHex(secp256k1.getPublicKey(singlePrivKey, true));
  const singleKeyLegacyOutput = new Output({
    descriptor: `pkh(${singlePubKeyHex})`,
    network: NETWORK
  });

  // 2) Raw private-key signer (all inputs)
  {
    const { txId: txIdA, vout: voutA } = await regtestUtils.faucetComplex(
      Buffer.from(singleKeyLegacyOutput.getScriptPubKey()),
      Number(INITIAL_VALUE)
    );
    const { txHex: txHexA } = await regtestUtils.fetch(txIdA);

    const { txId: txIdB, vout: voutB } = await regtestUtils.faucetComplex(
      Buffer.from(singleKeyLegacyOutput.getScriptPubKey()),
      Number(INITIAL_VALUE)
    );
    const { txHex: txHexB } = await regtestUtils.fetch(txIdB);

    const psbt = new btc.Transaction();
    const finalizeInputA = singleKeyLegacyOutput.updatePsbtAsInput({
      psbt,
      txHex: txHexA,
      vout: voutA
    });
    const finalizeInputB = singleKeyLegacyOutput.updatePsbtAsInput({
      psbt,
      txHex: txHexB,
      vout: voutB
    });
    segwitOutput.updatePsbtAsOutput({ psbt, value: twoInputFinalValue });

    signPrivKey({ psbt, privKey: singlePrivKey });
    finalizeInputA({ psbt });
    finalizeInputB({ psbt });

    await regtestUtils.broadcast(psbt.hex);
    await regtestUtils.verify({
      txId: psbt.id,
      address: finalAddress,
      vout: 0,
      value: Number(twoInputFinalValue)
    });
  }

  // 3) Raw private-key signer (single input)
  {
    const { txId, vout } = await regtestUtils.faucetComplex(
      Buffer.from(singleKeyLegacyOutput.getScriptPubKey()),
      Number(INITIAL_VALUE)
    );
    const { txHex } = await regtestUtils.fetch(txId);

    const psbt = new btc.Transaction();
    const finalizeInput = singleKeyLegacyOutput.updatePsbtAsInput({
      psbt,
      txHex,
      vout
    });
    segwitOutput.updatePsbtAsOutput({ psbt, value: singleInputFinalValue });

    signInputPrivKey({ psbt, index: 0, privKey: singlePrivKey });
    //signPrivKey({ psbt, privKey: singlePrivKey }); //this would also work
    finalizeInput({ psbt });

    await regtestUtils.broadcast(psbt.hex);
    await regtestUtils.verify({
      txId: psbt.id,
      address: finalAddress,
      vout: 0,
      value: Number(singleInputFinalValue)
    });
  }

  console.log('Scure integration test: OK');
})();
