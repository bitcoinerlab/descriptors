// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import { assertLedgerApp, importAndValidateLedgerBitcoin } from './client';
import type { LedgerClient, LedgerSession, LedgerStore } from './types';

type LedgerTransport = {
  send(cla: number, ins: number, p1: number, p2: number): Promise<Uint8Array>;
};

type LedgerTransportModule = {
  default: {
    create(
      openTimeout?: number,
      listenTimeout?: number
    ): Promise<LedgerTransport>;
  };
};

function importAndValidateTransport({
  mode,
  specifier
}: {
  mode: 'node-hid' | 'webhid' | 'webusb';
  specifier: string;
}): LedgerTransportModule {
  try {
    return (
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require(specifier) as LedgerTransportModule
    );
  } catch (error) {
    const errorCode =
      error instanceof Error && 'code' in error
        ? (error as Error & { code?: string }).code
        : undefined;
    if (
      error instanceof Error &&
      (errorCode === 'MODULE_NOT_FOUND' || error.message.includes(specifier))
    ) {
      throw new Error(
        `Could not import "${specifier}". This peer dependency is required when using Ledger ${mode} connector mode. Please run "npm install ${specifier}" or use connectors.fromClient(...).`
      );
    }
    throw error;
  }
}

/**
 * Build a Ledger session from an existing Ledger Bitcoin app client.
 *
 * Use this when your app owns the transport, for example React Native, BLE,
 * WebUSB/WebHID handled outside this package, or a custom provider.
 */
export function fromClient({
  client,
  Output,
  network,
  store
}: {
  /** Ledger Bitcoin app client instance. */
  client: LedgerClient;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** App-owned JSON store for cached keys and Ledger policy receipts. */
  store: LedgerStore;
}): LedgerSession {
  return {
    client,
    store,
    Output,
    network
  };
}

/**
 * Connect to a Ledger with one built-in transport mode and build a session.
 *
 * Install `@ledgerhq/ledger-bitcoin` plus the transport package for the selected
 * mode. Use `fromClient(...)` if your app already has a Ledger Bitcoin client.
 */
export async function connect(
  params:
    | {
        /**
         * Use Node.js HID. Install `@ledgerhq/ledger-bitcoin` and
         * `@ledgerhq/hw-transport-node-hid`.
         */
        mode: 'node-hid';
        /** Pre-bound `Output` constructor from the package/backend you are using. */
        Output: OutputConstructor;
        /** Bitcoin network used for descriptor and policy interpretation. */
        network: Network;
        /** App-owned JSON store for cached keys and Ledger policy receipts. */
        store: LedgerStore;
        /** Expected open Ledger app name. */
        appName?: string;
        /** Minimum acceptable Bitcoin app version. */
        minVersion?: string;
        /** Set to false if the caller validates the app separately. */
        assertApp?: boolean;
        /** Node HID open timeout in milliseconds. Default: 3000. */
        openTimeout?: number;
        /** Node HID listen timeout in milliseconds. Default: 3000. */
        listenTimeout?: number;
      }
    | {
        /**
         * Use browser WebHID. Install `@ledgerhq/ledger-bitcoin` and
         * `@ledgerhq/hw-transport-webhid`.
         */
        mode: 'webhid';
        /** Pre-bound `Output` constructor from the package/backend you are using. */
        Output: OutputConstructor;
        /** Bitcoin network used for descriptor and policy interpretation. */
        network: Network;
        /** App-owned JSON store for cached keys and Ledger policy receipts. */
        store: LedgerStore;
        /** Expected open Ledger app name. */
        appName?: string;
        /** Minimum acceptable Bitcoin app version. */
        minVersion?: string;
        /** Set to false if the caller validates the app separately. */
        assertApp?: boolean;
      }
    | {
        /**
         * Use browser WebUSB. Install `@ledgerhq/ledger-bitcoin` and
         * `@ledgerhq/hw-transport-webusb`.
         */
        mode: 'webusb';
        /** Pre-bound `Output` constructor from the package/backend you are using. */
        Output: OutputConstructor;
        /** Bitcoin network used for descriptor and policy interpretation. */
        network: Network;
        /** App-owned JSON store for cached keys and Ledger policy receipts. */
        store: LedgerStore;
        /** Expected open Ledger app name. */
        appName?: string;
        /** Minimum acceptable Bitcoin app version. */
        minVersion?: string;
        /** Set to false if the caller validates the app separately. */
        assertApp?: boolean;
      }
): Promise<LedgerSession> {
  const {
    Output,
    network,
    store,
    appName = 'Bitcoin',
    minVersion = '2.1.0',
    assertApp = true
  } = params;
  const transport =
    params.mode === 'node-hid'
      ? await importAndValidateTransport({
          mode: params.mode,
          specifier: '@ledgerhq/hw-transport-node-hid'
        }).default.create(
          params.openTimeout ?? 3000,
          params.listenTimeout ?? 3000
        )
      : await importAndValidateTransport({
          mode: params.mode,
          specifier:
            params.mode === 'webhid'
              ? '@ledgerhq/hw-transport-webhid'
              : '@ledgerhq/hw-transport-webusb'
        }).default.create();
  const ledgerBitcoin =
    (await importAndValidateLedgerBitcoin()) as typeof import('@ledgerhq/ledger-bitcoin');

  if (assertApp)
    await assertLedgerApp({ transport, name: appName, minVersion });

  return fromClient({
    client: new ledgerBitcoin.AppClient(
      transport as ConstructorParameters<typeof ledgerBitcoin.AppClient>[0]
    ),
    Output,
    network,
    store
  });
}
