// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import * as ecc from '@bitcoinerlab/secp256k1';
import { networks, Psbt, Transaction } from 'bitcoinjs-lib';
import { fromUtf8, toBase64, toHex } from 'uint8array-tools';
import type { BIP32InterfaceLike } from '../dist/bitcoinLib';
import {
  DescriptorsFactory,
  keyExpressionBIP32,
  signers as softwareSigners
} from '../dist';
import { createBitcoinjsLib } from '../dist/bitcoinjs';
import {
  connect,
  displayAddress,
  getVersion,
  getXpub,
  keyExpression,
  registerPolicy,
  scriptExpressions,
  signMessage,
  signers,
  type JadeDriverModule,
  type Session
} from '../dist/jade';

const NETWORK = networks.regtest;
const { Output, BIP32 } = DescriptorsFactory(createBitcoinjsLib(ecc));
const MESSAGE_SIGNATURE = new Uint8Array(65).fill(2);

type JadeClient = Session['client'];
type RegisteredDescriptor = Awaited<
  ReturnType<JadeClient['getRegisteredDescriptor']>
>;

type FakeJadeClient = JadeClient & {
  disconnect: jest.Mock<Promise<void>, []>;
  registeredDescriptors: Record<string, RegisteredDescriptor>;
  addressRequest:
    | {
        network: string;
        options: Parameters<JadeClient['getReceiveAddress']>[1];
      }
    | undefined;
  signedPsbt: Uint8Array | undefined;
  signedMessage: { path: number[]; message: string } | undefined;
};

function makeMaster(seed: number, network = NETWORK): BIP32InterfaceLike {
  return BIP32.fromSeed(new Uint8Array(32).fill(seed), network);
}

function derivePath(master: BIP32InterfaceLike, path: number[]) {
  return path.reduce((node, index) => node.derive(index), master);
}

function fakeClientFor(master: BIP32InterfaceLike): FakeJadeClient {
  const registeredDescriptors: Record<string, RegisteredDescriptor> = {};
  const client: FakeJadeClient = {
    registeredDescriptors,
    addressRequest: undefined as FakeJadeClient['addressRequest'],
    signedPsbt: undefined as Uint8Array | undefined,
    signedMessage: undefined as FakeJadeClient['signedMessage'],
    disconnect: jest.fn(async () => undefined),
    getVersionInfo: async () => ({ JADE_VERSION: '1.0.99-test' }),
    authUser: async () => true,
    getMasterFingerprint: async () => toHex(master.fingerprint),
    getXpub: async (_network, path) =>
      derivePath(master, path).neutered().toBase58(),
    getRegisteredDescriptors: async () =>
      Object.fromEntries(
        Object.entries(registeredDescriptors).map(([name, record]) => [
          name,
          {
            descriptor_len: record.descriptor.length,
            num_datavalues: Object.keys(record.datavalues).length
          }
        ])
      ),
    getRegisteredDescriptor: async name => {
      const descriptor = registeredDescriptors[name];
      if (!descriptor) throw new Error(`missing descriptor ${name}`);
      return descriptor;
    },
    registerDescriptor: async (_network, name, descriptor, datavalues) => {
      registeredDescriptors[name] = {
        descriptor_name: name,
        descriptor,
        datavalues
      };
      return true;
    },
    getReceiveAddress: async (network, options) => {
      client.addressRequest = { network, options };
      return 'bcrt1qjadetest';
    },
    signPSBT: async (_network, psbt) => {
      client.signedPsbt = psbt;
      return psbt;
    },
    signMessage: async (path, message) => {
      client.signedMessage = { path, message };
      return toBase64(MESSAGE_SIGNATURE);
    }
  };
  return client;
}

function sessionFor(master: BIP32InterfaceLike, client: JadeClient): Session {
  return {
    client,
    store: { masterFingerprint: toHex(master.fingerprint) },
    network: NETWORK,
    close: async () => undefined
  };
}

function addDescriptorInput({
  psbt,
  descriptor,
  index,
  seed
}: {
  psbt: Psbt;
  descriptor: string;
  index: number;
  seed: number;
}) {
  const output = new Output({
    descriptor,
    index,
    network: NETWORK,
    ...(/\/(?:\*\*|<[^<>]+>)/.test(descriptor) ? { change: 0 } : {})
  });
  const fundingTx = new Transaction();
  fundingTx.addInput(Buffer.alloc(32, seed), 0xffffffff);
  fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), 20_000n);
  output.updatePsbtAsInput({ psbt, txHex: fundingTx.toHex(), vout: 0 });
}

describe('Jade helpers', () => {
  test('connects, authenticates and owns the injected connection', async () => {
    const master = makeMaster(1);
    const client = fakeClientFor(master);
    const store = {};
    const httpRequest = jest.fn(async () => ({ body: {} }));
    const connectJadeUsb = jest.fn(async () => client);
    const authUser = jest.spyOn(client, 'authUser');
    const module = { connectJadeUsb } satisfies JadeDriverModule<string>;

    const session = await connect({
      driver: {
        module: Promise.resolve(module),
        mode: 'usb',
        device: 'usb-device',
        timeoutMs: 60_000,
        httpRequest
      },
      network: NETWORK,
      store
    });

    expect(connectJadeUsb).toHaveBeenCalledWith({
      device: 'usb-device',
      timeoutMs: 60_000
    });
    expect(authUser).toHaveBeenCalledWith('localtest', httpRequest);
    expect(store).toEqual({ masterFingerprint: toHex(master.fingerprint) });
    const closing = session.close();
    expect(session.close()).toBe(closing);
    await closing;
    expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  test('rejects missing modes and closes fingerprint mismatches', async () => {
    const master = makeMaster(2);
    const client = fakeClientFor(master);

    await expect(
      connect({
        driver: { module: {}, mode: 'ble' },
        network: NETWORK,
        store: {}
      })
    ).rejects.toThrow('Jade driver does not support mode "ble"');

    await expect(
      connect({
        driver: {
          module: { connectJadeTcp: async () => client },
          mode: 'tcp'
        },
        network: NETWORK,
        store: { masterFingerprint: 'deadbeef' }
      })
    ).rejects.toThrow('does not match store fingerprint deadbeef');
    expect(client.disconnect).toHaveBeenCalledTimes(1);
  });

  test.each(['denied', 'failed', 'invalid fingerprint'])(
    'closes the connection after authentication is %s',
    async failure => {
      const client = fakeClientFor(makeMaster(20));
      const store = {};
      if (failure === 'denied')
        jest.spyOn(client, 'authUser').mockResolvedValue(false);
      else if (failure === 'failed')
        jest
          .spyOn(client, 'authUser')
          .mockRejectedValue(new Error('PIN server unavailable'));
      else
        jest
          .spyOn(client, 'getMasterFingerprint')
          .mockResolvedValue('not-a-fingerprint');

      await expect(
        connect({
          driver: {
            module: { connectJadeUsb: async () => client },
            mode: 'usb'
          },
          network: NETWORK,
          store
        })
      ).rejects.toThrow();
      expect(client.disconnect).toHaveBeenCalledTimes(1);
      expect(store).toEqual({});
    }
  );

  test('builds standard descriptors and displays their addresses', async () => {
    const master = makeMaster(3);
    const client = fakeClientFor(master);
    const session = sessionFor(master, client);
    const descriptor = await scriptExpressions.wpkh({
      session,
      account: 0,
      change: 0,
      index: '*'
    });

    await expect(getVersion({ session })).resolves.toBe('1.0.99-test');
    await expect(getXpub({ session, originPath: "/84'/1'/0'" })).resolves.toBe(
      master.derivePath("84'/1'/0'").neutered().toBase58()
    );
    await expect(
      displayAddress({ descriptor, session, index: 7 })
    ).resolves.toBe('bcrt1qjadetest');
    expect(client.addressRequest).toEqual({
      network: 'localtest',
      options: {
        variant: 'wpkh(k)',
        path: [0x80000054, 0x80000001, 0x80000000, 0, 7]
      }
    });

    const taproot = await scriptExpressions.tr({
      session,
      account: 0,
      change: 0,
      index: '*'
    });
    await displayAddress({ descriptor: taproot, session, index: 2 });
    expect(client.addressRequest).toEqual({
      network: 'localtest',
      options: {
        variant: 'tr(k)',
        path: [0x80000056, 0x80000001, 0x80000000, 0, 2]
      }
    });
  });

  test('keeps cached xpubs separate by Jade network', async () => {
    const master = makeMaster(30);
    const client = fakeClientFor(master);
    const store = { masterFingerprint: toHex(master.fingerprint) };
    const getClientXpub = jest.spyOn(client, 'getXpub');
    const regtestSession = { ...sessionFor(master, client), store };
    const mainnetSession = {
      ...sessionFor(master, client),
      store,
      network: networks.bitcoin
    };

    await getXpub({ session: regtestSession, originPath: "/84'/1'/0'" });
    await getXpub({ session: mainnetSession, originPath: "/84'/1'/0'" });

    expect(getClientXpub).toHaveBeenNthCalledWith(
      1,
      'localtest',
      expect.any(Array)
    );
    expect(getClientXpub).toHaveBeenNthCalledWith(
      2,
      'mainnet',
      expect.any(Array)
    );
  });

  test('registers and displays a BIP388 Miniscript policy', async () => {
    const master = makeMaster(4);
    const client = fakeClientFor(master);
    const session = sessionFor(master, client);
    const jadeKey = await keyExpression({
      session,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/<0;1>/*'
    });
    const descriptor = `wsh(and_v(v:pk(${jadeKey}),older(5)))`;

    await expect(
      registerPolicy({ descriptor, session, name: 'Jade-CSV' })
    ).resolves.toBe(false);
    expect(client.registeredDescriptors['Jade-CSV']).toEqual({
      descriptor_name: 'Jade-CSV',
      descriptor: 'wsh(and_v(v:pk(@0/<0;1>/*),older(5)))',
      datavalues: {
        '@0': expect.stringContaining(
          `[${toHex(master.fingerprint)}/48'/1'/0'/2']`
        )
      }
    });
    expect(session.store.policies?.[0]).toMatchObject({
      name: 'Jade-CSV',
      descriptorTemplate: 'wsh(and_v(v:pk(@0/**),older(5)))'
    });

    await expect(
      registerPolicy({ descriptor, session, name: 'Jade-CSV' })
    ).resolves.toBe(true);
    await expect(
      displayAddress({ descriptor, session, change: 1, index: 9 })
    ).resolves.toBe('bcrt1qjadetest');
    expect(client.addressRequest).toEqual({
      network: 'localtest',
      options: { descriptorName: 'Jade-CSV', branch: 1, pointer: 9 }
    });

    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({ psbt, descriptor, index: 0, seed: 2 });
    await expect(signers.sign({ psbt, session })).resolves.toBeUndefined();
    expect(client.signedPsbt).toBeInstanceOf(Uint8Array);

    client.registeredDescriptors['Jade-CSV'] = {
      descriptor_name: 'Jade-CSV',
      descriptor: 'wsh(pk(@0/<0;1>/*))',
      datavalues: { '@0': 'different-key' }
    };
    client.addressRequest = undefined;
    await expect(
      displayAddress({ descriptor, session, change: 0, index: 1 })
    ).rejects.toThrow('already used by another policy');
    expect(client.addressRequest).toBeUndefined();
  });

  test('does not overwrite another Jade registration', async () => {
    const master = makeMaster(5);
    const client = fakeClientFor(master);
    const session = sessionFor(master, client);
    const jadeKey = await keyExpression({
      session,
      originPath: "/48'/1'/0'/2'",
      keyPath: '/0/*'
    });
    client.registeredDescriptors['Taken'] = {
      descriptor_name: 'Taken',
      descriptor: 'wsh(pk(@0/<0;1>/*))',
      datavalues: { '@0': 'different-key' }
    };

    await expect(
      registerPolicy({
        descriptor: `wsh(and_v(v:pk(${jadeKey}),older(5)))`,
        session,
        name: 'Taken'
      })
    ).rejects.toThrow('already used by another policy');
    expect(session.store.policies).toHaveLength(0);
  });

  test('rejects Taproot trees before registration or signing', async () => {
    const master = makeMaster(6);
    const otherMaster = makeMaster(7);
    const client = fakeClientFor(master);
    const session = sessionFor(master, client);
    const jadeKey = await keyExpression({
      session,
      originPath: "/86'/1'/0'",
      keyPath: '/0/*'
    });
    const otherKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath: "/86'/1'/0'",
      keyPath: '/0/*'
    });
    const descriptor = `tr(${otherKey},pk(${jadeKey}))`;

    await expect(
      registerPolicy({ descriptor, session, name: 'Tap-tree' })
    ).rejects.toThrow('Taproot trees and script-path spending');

    const output = new Output({
      descriptor,
      index: 0,
      network: NETWORK,
      taprootSpendPath: 'script'
    });
    const psbt = new Psbt({ network: NETWORK });
    const fundingTx = new Transaction();
    fundingTx.addInput(Buffer.alloc(32, 3), 0xffffffff);
    fundingTx.addOutput(Buffer.from(output.getScriptPubKey()), 20_000n);
    output.updatePsbtAsInput({
      psbt,
      txHex: fundingTx.toHex(),
      vout: 0
    });
    await expect(signers.sign({ psbt, session })).rejects.toThrow(
      'Taproot trees and script-path spending'
    );
    expect(client.signedPsbt).toBeUndefined();
  });

  test('lets Jade skip an unrelated Taproot script-path input', async () => {
    const master = makeMaster(60);
    const otherMaster = makeMaster(61);
    const otherLeafMaster = makeMaster(62);
    const client = fakeClientFor(master);
    const session = sessionFor(master, client);
    const ownedDescriptor = await scriptExpressions.wpkh({
      session,
      account: 0,
      change: 0,
      index: '*'
    });
    const otherInternalKey = keyExpressionBIP32({
      masterNode: otherMaster,
      originPath: "/86'/1'/0'",
      keyPath: '/0/*'
    });
    const otherLeafKey = keyExpressionBIP32({
      masterNode: otherLeafMaster,
      originPath: "/86'/1'/0'",
      keyPath: '/0/*'
    });
    const unrelatedOutput = new Output({
      descriptor: `tr(${otherInternalKey},pk(${otherLeafKey}))`,
      index: 0,
      network: NETWORK,
      taprootSpendPath: 'script'
    });
    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({
      psbt,
      descriptor: ownedDescriptor,
      index: 0,
      seed: 10
    });
    const unrelatedFunding = new Transaction();
    unrelatedFunding.addInput(Buffer.alloc(32, 11), 0xffffffff);
    unrelatedFunding.addOutput(
      Buffer.from(unrelatedOutput.getScriptPubKey()),
      20_000n
    );
    unrelatedOutput.updatePsbtAsInput({
      psbt,
      txHex: unrelatedFunding.toHex(),
      vout: 0
    });

    await expect(signers.sign({ psbt, session })).resolves.toBeUndefined();
    expect(client.signedPsbt).toBeInstanceOf(Uint8Array);
    expect(
      Psbt.fromBuffer(Buffer.from(client.signedPsbt!), { network: NETWORK })
        .data.inputs
    ).toHaveLength(2);
  });

  test.each(['wpkh', 'tr'] as const)(
    'merges Jade %s signatures without changing the transaction',
    async variant => {
      const master = makeMaster(8);
      const client = fakeClientFor(master);
      const session = sessionFor(master, client);
      const descriptor = await scriptExpressions[variant]({
        session,
        account: 0,
        change: 0,
        index: '*'
      });
      const output = new Output({ descriptor, index: 0, network: NETWORK });
      const psbt = new Psbt({ network: NETWORK });
      addDescriptorInput({ psbt, descriptor, index: 0, seed: 1 });
      output.updatePsbtAsOutput({ psbt, value: 19_000n });
      jest
        .spyOn(client, 'signPSBT')
        .mockImplementation(async (_network, raw) => {
          const signed = Psbt.fromBuffer(Buffer.from(raw), {
            network: NETWORK
          });
          softwareSigners.signBIP32({ psbt: signed, masterNode: master });
          return signed.toBuffer();
        });

      await expect(signers.sign({ psbt, session })).resolves.toBeUndefined();
      expect(client.signPSBT).toHaveBeenCalledWith(
        'localtest',
        expect.any(Uint8Array)
      );
      if (variant === 'wpkh')
        expect(psbt.data.inputs[0]?.partialSig).toHaveLength(1);
      else expect(psbt.data.inputs[0]?.tapKeySig).toHaveLength(64);
      expect(psbt.txOutputs[0]?.value).toBe(19_000n);
    }
  );

  test('rejects a returned PSBT with a different transaction', async () => {
    const client = fakeClientFor(makeMaster(25));
    const session = sessionFor(makeMaster(25), client);
    const descriptor = await scriptExpressions.wpkh({
      session,
      account: 0,
      change: 0,
      index: '*'
    });
    const psbt = new Psbt({ network: NETWORK });
    addDescriptorInput({ psbt, descriptor, index: 0, seed: 1 });
    new Output({ descriptor, index: 1, network: NETWORK }).updatePsbtAsOutput({
      psbt,
      value: 19_000n
    });
    const before = psbt.toBase64();
    jest.spyOn(client, 'signPSBT').mockImplementation(async (_network, raw) => {
      const changed = Psbt.fromBuffer(Buffer.from(raw), { network: NETWORK });
      changed.setLocktime(42);
      return changed.toBuffer();
    });

    await expect(signers.sign({ psbt, session })).rejects.toThrow();
    expect(psbt.toBase64()).toBe(before);
  });

  test('signs UTF-8 messages for standard non-Taproot descriptors', async () => {
    const master = makeMaster(9);
    const client = fakeClientFor(master);
    const session = sessionFor(master, client);
    const descriptor = await scriptExpressions.pkh({
      session,
      account: 0,
      change: 0,
      index: '*'
    });

    await expect(
      signMessage({
        descriptor,
        session,
        message: fromUtf8('hello'),
        index: 0
      })
    ).resolves.toEqual(MESSAGE_SIGNATURE);
    expect(client.signedMessage).toEqual({
      path: [0x8000002c, 0x80000001, 0x80000000, 0, 0],
      message: 'hello'
    });

    const taproot = await scriptExpressions.tr({
      session,
      account: 0,
      change: 0,
      index: '*'
    });
    await expect(
      signMessage({ descriptor: taproot, session, message: 'hello', index: 0 })
    ).rejects.toThrow('supports only standard single-key pkh');
  });
});
