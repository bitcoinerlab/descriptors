// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { base64 } from '@scure/base';
import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import * as ledgerBitcoinApi from '@ledgerhq/ledger-bitcoin';
import { Transaction as BitcoinjsTransaction } from 'bitcoinjs-lib';
import { DescriptorsFactory, keyExpressionBIP32, networks } from '../dist';
import { createScureLib } from '../dist/scure';
import { signers, type Session } from '../dist/ledger';

const NETWORK = networks.regtest;
const { Output } = DescriptorsFactory(createScureLib());
const BITCOIN_API = {
  WalletPolicy: ledgerBitcoinApi.WalletPolicy,
  DefaultWalletPolicy: ledgerBitcoinApi.DefaultWalletPolicy
} as Session['bitcoinApi'];

function signingFixture(seed: number) {
  const master = HDKey.fromMasterSeed(
    new Uint8Array(32).fill(seed),
    NETWORK.bip32
  );
  const masterFingerprint = master.fingerprint.toString(16).padStart(8, '0');
  const account = master.derive("m/84'/1'/0'");
  const key = keyExpressionBIP32({
    masterNode: master,
    originPath: "/84'/1'/0'",
    keyPath: '/0/*'
  });
  const output = new Output({
    descriptor: `wpkh(${key})`,
    index: 0,
    network: NETWORK
  });
  const fundingTx = new BitcoinjsTransaction();
  fundingTx.addInput(Buffer.alloc(32, seed), 0xffffffff);
  fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), 20_000n);
  const psbt = new btc.Transaction({ disableScriptCheck: true });
  const finalize = output.updatePsbtAsInput({
    psbt,
    txHex: fundingTx.toHex(),
    vout: 0
  });
  output.updatePsbtAsOutput({ psbt, value: 19_000n });

  const signPsbt = jest.fn(async (psbtBase64: string) => {
    const signed = btc.Transaction.fromPSBT(base64.decode(psbtBase64));
    const privateKey = master.derive("m/84'/1'/0'/0/0").privateKey;
    if (!privateKey) throw new Error('missing test private key');
    expect(signed.sign(privateKey)).toBe(1);
    const partialSig = signed.getInput(0).partialSig?.[0];
    if (!partialSig) throw new Error('Ledger test signature missing');
    const [pubkey, signature] = partialSig;
    return [[0, { pubkey, signature }]] as Awaited<
      ReturnType<Session['client']['signPsbt']>
    >;
  });
  const session = {
    client: { signPsbt } as unknown as Session['client'],
    bitcoinApi: BITCOIN_API,
    network: NETWORK,
    store: {
      masterFingerprint,
      xpubs: { "/84'/1'/0'": account.publicExtendedKey }
    },
    close: async () => undefined
  } satisfies Session;
  return { finalize, psbt, session, signPsbt };
}

test('signs Scure inputs through the modern Ledger session API', async () => {
  const { finalize, psbt, session, signPsbt } = signingFixture(33);

  await signers.signInput({ psbt, index: 0, session });

  expect(signPsbt).toHaveBeenCalledTimes(1);
  expect(psbt.getInput(0).partialSig).toHaveLength(1);
  finalize({ psbt, validate: false });
  expect(psbt.getInput(0).finalScriptWitness).toBeDefined();
});

test('signs owned Scure inputs while skipping unrelated inputs', async () => {
  const { psbt, session, signPsbt } = signingFixture(34);
  psbt.addInput({
    txid: new Uint8Array(32).fill(2),
    index: 0,
    witnessUtxo: { script: new Uint8Array([0x51]), amount: 10_000n }
  });
  psbt.addInput({ txid: new Uint8Array(32).fill(3), index: 0 });

  await signers.sign({ psbt, session });

  expect(signPsbt).toHaveBeenCalledTimes(1);
  expect(psbt.getInput(0).partialSig).toHaveLength(1);
  expect(psbt.getInput(1).partialSig).toBeUndefined();
  expect(psbt.getInput(2).partialSig).toBeUndefined();
});
