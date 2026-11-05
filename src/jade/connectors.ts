// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { Network } from '../networks';
import { jadeNetwork } from './client';
import type {
  ConnectedJadeClient,
  JadeConnectionMode,
  JadeDriverModule,
  JadeHttpRequestFunction,
  JadeSession,
  JadeStore
} from './types';

/** Opens an injected USB, BLE or development TCP Jade driver. */
export async function connect<TDevice = unknown>({
  driver,
  network,
  store
}: {
  driver: {
    module: JadeDriverModule<TDevice> | Promise<JadeDriverModule<TDevice>>;
    mode: JadeConnectionMode;
    device?: TDevice;
    timeoutMs?: number;
    /** Handles Jade blind-pinserver requests when the driver has no default. */
    httpRequest?: JadeHttpRequestFunction;
  };
  network: Network;
  store: JadeStore;
}): Promise<JadeSession> {
  const driverModule = await driver.module;
  const open =
    driver.mode === 'usb'
      ? driverModule.connectJadeUsb
      : driver.mode === 'ble'
        ? driverModule.connectJadeBle
        : driver.mode === 'tcp'
          ? driverModule.connectJadeTcp
          : undefined;
  if (typeof open !== 'function')
    throw new Error(`Jade driver does not support mode "${driver.mode}"`);

  const client: ConnectedJadeClient = await open({
    ...(driver.device !== undefined ? { device: driver.device } : {}),
    ...(driver.timeoutMs !== undefined ? { timeoutMs: driver.timeoutMs } : {})
  });

  try {
    if (typeof client.disconnect !== 'function')
      throw new Error(`Jade client must have a disconnect method`);

    const apiNetwork = jadeNetwork(network);
    const authenticated = await client.authUser(apiNetwork, driver.httpRequest);
    if (!authenticated) throw new Error(`Jade authentication failed`);

    const masterFingerprint = (
      await client.getMasterFingerprint(apiNetwork)
    ).toLowerCase();
    if (!/^[0-9a-f]{8}$/.test(masterFingerprint))
      throw new Error(`Jade returned an invalid master fingerprint`);
    if (
      store.masterFingerprint !== undefined &&
      store.masterFingerprint.toLowerCase() !== masterFingerprint
    )
      throw new Error(
        `Connected Jade fingerprint ${masterFingerprint} does not match store fingerprint ${store.masterFingerprint}`
      );
    store.masterFingerprint = masterFingerprint;

    let closing: Promise<void> | undefined;
    return {
      client,
      network,
      store,
      close: () => {
        closing ??= Promise.resolve().then(() => client.disconnect());
        return closing;
      }
    };
  } catch (error) {
    try {
      await client.disconnect();
    } catch {
      // Keep the connection or validation error that caused cleanup.
    }
    throw error;
  }
}
