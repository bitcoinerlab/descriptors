// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { base64 } from '@scure/base';
import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import { Transaction as BitcoinjsTransaction } from 'bitcoinjs-lib';
import { DescriptorsFactory, networks } from '../dist';
import { createScureLib } from '../dist/scure';
import {
  connectors,
  scriptExpressions,
  signers,
  type BitBoxClient
} from '../dist/bitbox';

const NETWORK = networks.regtest;
const { Output } = DescriptorsFactory(createScureLib());

test('merges BitBox signatures into scure transactions', async () => {
  const master = HDKey.fromMasterSeed(
    new Uint8Array(32).fill(21),
    NETWORK.bip32
  );
  const masterFingerprint = master.fingerprint.toString(16).padStart(8, '0');
  const client = {
    version: () => '9.99.0-test',
    rootFingerprint: () => masterFingerprint,
    btcXpub: async (_network, keypath) => {
      if (typeof keypath !== 'string')
        throw new Error('unexpected number path');
      return master.derive(keypath).publicExtendedKey;
    },
    btcAddress: async () => 'bcrt1test',
    btcRegisterScriptConfig: async () => undefined,
    btcIsScriptConfigRegistered: async () => false,
    btcSignPSBT: async (_network, psbtBase64) => {
      const signed = btc.Transaction.fromPSBT(base64.decode(psbtBase64));
      const privateKey = master.derive("m/84'/1'/0'/0/0").privateKey;
      if (!privateKey) throw new Error('missing test private key');
      expect(signed.sign(privateKey)).toBe(1);
      return base64.encode(signed.toPSBT());
    }
  } satisfies BitBoxClient;
  const session = connectors.fromClient({
    client,
    network: NETWORK,
    store: { masterFingerprint }
  });
  const descriptor = await scriptExpressions.wpkh({
    session,
    account: 0,
    change: 0,
    index: '*'
  });
  const output = new Output({ descriptor, index: 0, network: NETWORK });
  const fundingTx = new BitcoinjsTransaction();
  fundingTx.addInput(Buffer.alloc(32, 1), 0xffffffff);
  fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), 20_000n);
  const psbt = new btc.Transaction({ disableScriptCheck: true });
  const finalize = output.updatePsbtAsInput({
    psbt,
    txHex: fundingTx.toHex(),
    vout: 0
  });
  output.updatePsbtAsOutput({ psbt, value: 19_000n });

  await signers.sign({ psbt, session });

  expect(psbt.getInput(0).partialSig).toHaveLength(1);
  finalize({ psbt });
  expect(psbt.getInput(0).finalScriptWitness).toBeDefined();
});
