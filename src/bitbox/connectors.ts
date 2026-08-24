// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { Network } from '../networks';
import type {
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxSession,
  BitBoxStore
} from './types';

type ConnectedBitBoxClient = BitBoxClient & {
  close(): void | Promise<void>;
};

type BitBoxPairing = {
  free?(): void;
  getPairingCode(): string | undefined;
  waitConfirm(): Promise<ConnectedBitBoxClient>;
};

type BitBoxConnection = {
  unlockAndPair(): Promise<BitBoxPairing>;
};

type ConnectBitBox = (params?: {
  timeoutMs?: number;
  deviceId?: string;
}) => Promise<ConnectedBitBoxClient>;

type BitBoxReactNativeModule = {
  connectBitBoxNovaBle?: ConnectBitBox;
  connectBitBoxUsb?: ConnectBitBox;
};

type BitBoxApiConnect = (
  onClose: (() => void) | undefined
) => Promise<BitBoxConnection>;

type BitBoxApiModule = {
  bitbox02ConnectAuto?: BitBoxApiConnect;
  bitbox02ConnectBridge?: BitBoxApiConnect;
  bitbox02ConnectWebHID?: BitBoxApiConnect;
};

type BitBoxDriver =
  | {
      /** Imported BitBox React Native module, or its import promise. */
      module: BitBoxReactNativeModule | Promise<BitBoxReactNativeModule>;
      /** Select BLE or USB. */
      mode: 'ble' | 'usb';
      /** Device returned by provider discovery, or a saved device id. */
      device?: string | { deviceId: string };
      /** Timeout passed to the native BitBox provider. */
      timeoutMs?: number;
      /** Default amount unit shown while signing. */
      formatUnit?: BitBoxFormatUnit;
    }
  | {
      /** Imported `bitbox-api` module, or its import promise. */
      module: BitBoxApiModule | Promise<BitBoxApiModule>;
      /** Select the browser or bridge connection mechanism. */
      mode: 'webhid' | 'bridge' | 'webhid-or-bridge';
      /** Shows the code that the user must compare with the BitBox. */
      onPairingCode(code: string): void | Promise<void>;
      /** Called when `bitbox-api` reports a closed connection. */
      onClose?: () => void;
      /** Default amount unit shown while signing. */
      formatUnit?: BitBoxFormatUnit;
    };

/**
 * Opens a BitBox driver supplied by the application and builds a session.
 *
 * Pass a literal module import in `driver.module`, for example
 * `import('@bitcoinerlab/bitbox-react-native')`, and select `driver.mode`.
 *
 * The returned session owns the client. Call `session.close()` when the
 * connection is no longer needed.
 */
export async function connect({
  driver,
  network,
  store
}: {
  /** Everything specific to the selected BitBox driver. */
  driver: BitBoxDriver;
  /** Bitcoin network used for descriptors and policies. */
  network: Network;
  /** App-owned JSON store for cached keys and hardware-wallet policies. */
  store: BitBoxStore;
}): Promise<BitBoxSession> {
  const driverModule = await driver.module;
  const { mode } = driver;

  let client: ConnectedBitBoxClient;
  if (mode === 'ble' || mode === 'usb') {
    const connect =
      mode === 'ble'
        ? 'connectBitBoxNovaBle' in driverModule
          ? driverModule.connectBitBoxNovaBle
          : undefined
        : 'connectBitBoxUsb' in driverModule
          ? driverModule.connectBitBoxUsb
          : undefined;
    if (typeof connect !== 'function')
      throw new Error(`BitBox driver does not support mode "${mode}"`);
    if ('onPairingCode' in driver)
      throw new Error(`BitBox React Native driver options are invalid`);
    const deviceId =
      typeof driver.device === 'string'
        ? driver.device
        : driver.device?.deviceId;
    client = await connect({
      ...(driver.timeoutMs !== undefined
        ? { timeoutMs: driver.timeoutMs }
        : {}),
      ...(deviceId !== undefined ? { deviceId } : {})
    });
  } else {
    if (!('onPairingCode' in driver))
      throw new Error(`BitBox API drivers require onPairingCode`);
    const connect =
      mode === 'webhid'
        ? 'bitbox02ConnectWebHID' in driverModule
          ? driverModule.bitbox02ConnectWebHID
          : undefined
        : mode === 'bridge'
          ? 'bitbox02ConnectBridge' in driverModule
            ? driverModule.bitbox02ConnectBridge
            : undefined
          : 'bitbox02ConnectAuto' in driverModule
            ? driverModule.bitbox02ConnectAuto
            : undefined;
    if (typeof connect !== 'function')
      throw new Error(`BitBox driver does not support mode "${mode}"`);
    const unpaired = await connect(driver.onClose);
    const pairing = await unpaired.unlockAndPair();
    try {
      const pairingCode = pairing.getPairingCode();
      if (pairingCode !== undefined) await driver.onPairingCode(pairingCode);
    } catch (error) {
      try {
        pairing.free?.();
      } catch {
        // Keep the error from the pairing-code callback.
      }
      throw error;
    }
    client = await pairing.waitConfirm();
  }

  try {
    if (typeof client.close !== 'function')
      throw new Error(`BitBox client must have a close method`);
    const masterFingerprint = (await client.rootFingerprint()).toLowerCase();
    if (!/^[0-9a-f]{8}$/.test(masterFingerprint))
      throw new Error(`BitBox returned an invalid master fingerprint`);
    if (
      store.masterFingerprint !== undefined &&
      store.masterFingerprint.toLowerCase() !== masterFingerprint
    )
      throw new Error(
        `Connected BitBox fingerprint ${masterFingerprint} does not match store fingerprint ${store.masterFingerprint}`
      );
    store.masterFingerprint = masterFingerprint;

    let closing: Promise<void> | undefined;
    return {
      client,
      network,
      store,
      ...('formatUnit' in driver && driver.formatUnit !== undefined
        ? { formatUnit: driver.formatUnit }
        : {}),
      close: () => {
        closing ??= Promise.resolve().then(() => client.close());
        return closing;
      }
    };
  } catch (error) {
    try {
      await client.close();
    } catch {
      // Keep the connection or validation error that caused cleanup.
    }
    throw error;
  }
}
