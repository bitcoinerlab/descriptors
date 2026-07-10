// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { Network } from '../networks';
import { assertLedgerApp, importLedgerBitcoinModule } from './client';
import type { LedgerClient, LedgerSession, LedgerStore } from './types';

type LedgerTransport = {
  send(cla: number, ins: number, p1: number, p2: number): Promise<Uint8Array>;
  close(): void | Promise<void>;
};

type LedgerTransportModule<TDevice> = {
  default: {
    create(
      openTimeout?: number,
      listenTimeout?: number
    ): Promise<LedgerTransport>;
    open(device: TDevice, openTimeout?: number): Promise<LedgerTransport>;
  };
};

/**
 * Builds a Ledger session from a client that the application already owns.
 *
 * Descriptors does not close this client. The application remains responsible
 * for its transport and connection lifetime.
 */
export function fromClient({
  client,
  network,
  store
}: {
  /** Ledger Bitcoin app client instance. */
  client: LedgerClient;
  /** Bitcoin network used for descriptors and policies. */
  network: Network;
  /** App-owned JSON store for cached keys and Ledger policy receipts. */
  store: LedgerStore;
}): LedgerSession {
  return { client, store, network };
}

/**
 * Opens a Ledger transport supplied by the application and builds a session.
 *
 * Pass a literal module import in `driver.module`, for example
 * `import('@ledgerhq/react-native-hid')`. This lets Metro and other bundlers see
 * the selected optional dependency. If `driver.device` is omitted, the Ledger
 * transport's normal `create()` behavior is used.
 *
 * The returned session owns the transport. Call `session.close()` when the
 * connection is no longer needed.
 */
export async function connect<TDevice>({
  driver,
  network,
  store
}: {
  /** Everything specific to the selected Ledger transport and app. */
  driver: {
    /** Imported Ledger transport module, or its import promise. */
    module:
      | LedgerTransportModule<TDevice>
      | Promise<LedgerTransportModule<TDevice>>;
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
}): Promise<
  LedgerSession & {
    /** Closes the transport owned by this connected session. */
    close(): Promise<void>;
  }
> {
  const [transportModule, ledgerBitcoin] = await Promise.all([
    driver.module,
    importLedgerBitcoinModule()
  ]);
  const Transport = transportModule.default;
  if (!Transport)
    throw new Error(`Ledger driver must have a default transport export`);

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

    const client: LedgerClient = new ledgerBitcoin.AppClient(
      transport as ConstructorParameters<typeof ledgerBitcoin.AppClient>[0]
    );
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
      ...fromClient({ client, network, store }),
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
