// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { HDKey } from '@scure/bip32';
import * as btc from '@scure/btc-signer';
import { Transaction as BitcoinjsTransaction } from 'bitcoinjs-lib';
import { DescriptorsFactory, networks } from '../dist';
import { createScureLib } from '../dist/scure';
import { scriptExpressions, signers, type Session } from '../dist/jade';

const NETWORK = networks.regtest;
const { Output } = DescriptorsFactory(createScureLib());

test.each(['wpkh', 'tr'] as const)(
  'merges Jade %s signatures into scure transactions',
  async variant => {
    const master = HDKey.fromMasterSeed(
      new Uint8Array(32).fill(21),
      NETWORK.bip32
    );
    const masterFingerprint = master.fingerprint.toString(16).padStart(8, '0');
    const client = {
      getVersionInfo: async () => ({ JADE_VERSION: '1.0.99-test' }),
      authUser: async () => true,
      getMasterFingerprint: async () => masterFingerprint,
      getXpub: async (_network, path) => {
        const keypath = path
          .map(value =>
            value >= 0x80000000 ? `${value - 0x80000000}'` : `${value}`
          )
          .join('/');
        return master.derive(`m/${keypath}`).publicExtendedKey;
      },
      getRegisteredDescriptors: async () => ({}),
      getRegisteredDescriptor: async () => {
        throw new Error('not registered');
      },
      registerDescriptor: async () => true,
      getReceiveAddress: async () => 'bcrt1test',
      signMessage: async () => new Uint8Array(65),
      signPSBT: async (_network, psbtBytes) => {
        const signed = btc.Transaction.fromPSBT(psbtBytes);
        const purpose = variant === 'wpkh' ? 84 : 86;
        const privateKey = master.derive(`m/${purpose}'/1'/0'/0/0`).privateKey;
        if (!privateKey) throw new Error('missing test private key');
        expect(signed.sign(privateKey)).toBe(1);
        return signed.toPSBT();
      }
    } satisfies Session['client'];
    const session = {
      client,
      network: NETWORK,
      store: { masterFingerprint },
      close: async () => undefined
    } satisfies Session;
    const descriptor = await scriptExpressions[variant]({
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
    output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });
    output.updatePsbtAsOutput({ psbt, value: 19_000n });

    await signers.sign({ psbt, session });

    if (variant === 'wpkh') expect(psbt.getInput(0).partialSig).toHaveLength(1);
    else expect(psbt.getInput(0).tapKeySig).toHaveLength(64);
  }
);
