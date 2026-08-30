// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { Network } from '../networks';
import { assertLedgerApp } from './client';
import type {
  LedgerBitcoinApi,
  LedgerSession,
  LedgerStore,
  LedgerTransport
} from './types';

type LedgerTransportModule<TDevice, TTransport extends LedgerTransport> = {
  default: {
    create(openTimeout?: number, listenTimeout?: number): Promise<TTransport>;
    open(device: TDevice, openTimeout?: number): Promise<TTransport>;
  };
};

/**
 * Opens a Ledger transport supplied by the application and builds a session.
 *
 * Pass literal module imports in `driver.transport` and `driver.bitcoinApi`.
 * This lets Metro and other bundlers see both Ledger dependencies. If
 * `driver.device` is omitted, the transport's normal `create()` behavior is
 * used.
 *
 * The returned session owns the transport. Call `session.close()` when the
 * connection is no longer needed.
 */
export async function connect<TDevice, TTransport extends LedgerTransport>({
  driver,
  network,
  store
}: {
  /** Everything specific to the selected Ledger transport and Bitcoin API. */
  driver: {
    /** Imported Ledger transport module, or its import promise. */
    transport:
      | LedgerTransportModule<TDevice, TTransport>
      | Promise<LedgerTransportModule<TDevice, TTransport>>;
    /** Imported `@ledgerhq/ledger-bitcoin` module, or its import promise. */
    bitcoinApi:
      | LedgerBitcoinApi<TTransport>
      | Promise<LedgerBitcoinApi<TTransport>>;
    /** Device descriptor returned by the transport's discovery API. */
    device?: TDevice;
    /** Timeout passed to the transport while opening a device. */
    openTimeout?: number;
    /** Timeout passed to automatic transport discovery. */
    listenTimeout?: number;
    /** Optional Ledger app name and minimum version check. */
    app?: { name: string; minVersion: string };
  };
  /** Bitcoin network used for descriptors and policies. */
  network: Network;
  /** App-owned JSON store for cached keys and Ledger policy receipts. */
  store: LedgerStore;
}): Promise<LedgerSession> {
  const [transportModule, bitcoinApi] = await Promise.all([
    driver.transport,
    driver.bitcoinApi
  ]);
  const Transport = transportModule.default;
  if (!Transport)
    throw new Error(`Ledger driver must have a default transport export`);
  if (
    typeof bitcoinApi.AppClient !== 'function' ||
    typeof bitcoinApi.WalletPolicy !== 'function' ||
    typeof bitcoinApi.DefaultWalletPolicy !== 'function'
  )
    throw new Error(`Ledger bitcoinApi is missing required constructors`);

  const transport =
    driver.device === undefined
      ? driver.listenTimeout !== undefined
        ? await Transport.create(
            driver.openTimeout ?? 3000,
            driver.listenTimeout
          )
        : driver.openTimeout !== undefined
          ? await Transport.create(driver.openTimeout)
          : await Transport.create()
      : driver.openTimeout !== undefined
        ? await Transport.open(driver.device, driver.openTimeout)
        : await Transport.open(driver.device);

  try {
    if (typeof transport.close !== 'function')
      throw new Error(`Ledger transport must have a close method`);
    if (driver.app)
      await assertLedgerApp({
        transport,
        name: driver.app.name,
        minVersion: driver.app.minVersion
      });

    const client = new bitcoinApi.AppClient(transport);
    const masterFingerprint = (
      await client.getMasterFingerprint()
    ).toLowerCase();
    if (!/^[0-9a-f]{8}$/.test(masterFingerprint))
      throw new Error(`Ledger returned an invalid master fingerprint`);
    if (
      store.masterFingerprint !== undefined &&
      store.masterFingerprint.toLowerCase() !== masterFingerprint
    )
      throw new Error(
        `Connected Ledger fingerprint ${masterFingerprint} does not match store fingerprint ${store.masterFingerprint}`
      );
    store.masterFingerprint = masterFingerprint;

    let closing: Promise<void> | undefined;
    return {
      client,
      bitcoinApi,
      network,
      store,
      close: () => {
        closing ??= Promise.resolve().then(() => transport.close());
        return closing;
      }
    };
  } catch (error) {
    try {
      await transport.close();
    } catch {
      // Keep the connection or validation error that caused cleanup.
    }
    throw error;
  }
}
