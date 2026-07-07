// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import type {
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxSession,
  BitBoxStore
} from './types';

type BitBoxConnection = {
  unlockAndPair(): Promise<BitBoxPairing>;
};

type BitBoxPairing = {
  getPairingCode(): string | undefined;
  waitConfirm(): Promise<BitBoxClient>;
};

type BitBoxApiModule = {
  bitbox02ConnectAuto(onCloseCb?: () => void): Promise<BitBoxConnection>;
  bitbox02ConnectBridge(onCloseCb?: () => void): Promise<BitBoxConnection>;
  bitbox02ConnectWebHID(onCloseCb?: () => void): Promise<BitBoxConnection>;
};

type ImportBitBoxApi = (specifier: string) => Promise<BitBoxApiModule>;

let importBitBoxApi: ImportBitBoxApi | undefined;

// bitbox-api is ESM and loads a WASM file, so require('bitbox-api') does not
// work from this CommonJS build. This helper creates a native dynamic import
// function only when built-in connectors are used, keeping simple
// fromClient(...) imports safe for React Native users that provide their own
// connected client.
function getImportBitBoxApi(): ImportBitBoxApi {
  if (!importBitBoxApi) {
    try {
      importBitBoxApi = new Function(
        'specifier',
        'return import(specifier)'
      ) as ImportBitBoxApi;
    } catch (error) {
      void error;
      throw new Error(
        'BitBox built-in connectors require native dynamic import support. In React Native, use connectors.fromClient(...) with a platform provider instead.'
      );
    }
  }
  return importBitBoxApi;
}

async function importAndValidateBitBoxApi(): Promise<BitBoxApiModule> {
  try {
    return await getImportBitBoxApi()('bitbox-api');
  } catch (error) {
    const errorCode =
      error instanceof Error && 'code' in error
        ? (error as Error & { code?: string }).code
        : undefined;
    if (
      error instanceof Error &&
      (errorCode === 'MODULE_NOT_FOUND' ||
        errorCode === 'ERR_MODULE_NOT_FOUND' ||
        error.message.includes('bitbox-api'))
    ) {
      throw new Error(
        'Could not import "bitbox-api". This peer dependency is required when using BitBox built-in connectors. Please run "npm install bitbox-api" or use connectors.fromClient(...).'
      );
    }
    throw error;
  }
}

export type FromClientParams = {
  /** Connected and paired BitBox-compatible provider client. */
  client: BitBoxClient;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** App-owned JSON store for cached keys and wallet policy metadata. */
  store: BitBoxStore;
  /** Optional display unit passed to `btcSignPSBT`. */
  formatUnit?: BitBoxFormatUnit;
};

/**
 * Build a BitBox session from an already paired client.
 *
 * Use this in React Native or when your app owns the BitBox transport.
 */
export function fromClient({
  client,
  Output,
  network,
  store,
  formatUnit
}: FromClientParams): BitBoxSession {
  const session: BitBoxSession = {
    client,
    store,
    Output,
    network
  };
  if (formatUnit !== undefined) session.formatUnit = formatUnit;
  return session;
}

/**
 * Built-in BitBox connection modes.
 *
 * Install `bitbox-api` before using any of these modes. React Native apps
 * should usually use `fromClient(...)` instead.
 */
export type ConnectMode = 'webhid' | 'bridge' | 'webhid-or-bridge';

export type ConnectParams = Omit<FromClientParams, 'client'> & {
  /**
   * Built-in BitBox connection mode.
   *
   * Install `bitbox-api` before using this. `webhid` uses browser WebHID.
   * `bridge` uses BitBoxBridge. `webhid-or-bridge` tries WebHID and falls
   * back to BitBoxBridge.
   */
  mode: ConnectMode;
  /** Called when bitbox-api reports that the device connection closed. */
  onClose?: () => void;
  /** Called with the pairing code before waiting for device confirmation. */
  onPairingCode?: (pairingCode: string) => void | Promise<void>;
};

const connectNames: Record<
  ConnectMode,
  keyof Pick<
    BitBoxApiModule,
    'bitbox02ConnectAuto' | 'bitbox02ConnectBridge' | 'bitbox02ConnectWebHID'
  >
> = {
  'webhid-or-bridge': 'bitbox02ConnectAuto',
  bridge: 'bitbox02ConnectBridge',
  webhid: 'bitbox02ConnectWebHID'
};

async function connectWith(
  connectName: keyof Pick<
    BitBoxApiModule,
    'bitbox02ConnectAuto' | 'bitbox02ConnectBridge' | 'bitbox02ConnectWebHID'
  >,
  params: Omit<ConnectParams, 'mode'>
): Promise<BitBoxSession> {
  const bitboxApi = await importAndValidateBitBoxApi();
  const unpaired = await bitboxApi[connectName](params.onClose);
  const pairing = await unpaired.unlockAndPair();
  const pairingCode = pairing.getPairingCode();
  if (pairingCode !== undefined) await params.onPairingCode?.(pairingCode);
  const client = await pairing.waitConfirm();

  return fromClient({
    client,
    Output: params.Output,
    network: params.network,
    store: params.store,
    ...(params.formatUnit !== undefined
      ? { formatUnit: params.formatUnit }
      : {})
  });
}

/**
 * Connect to a BitBox with `bitbox-api` and build a session.
 *
 * Install `bitbox-api` before calling this. Use `fromClient(...)` if your app
 * already has a paired BitBox client.
 */
export async function connect({
  mode,
  ...params
}: ConnectParams): Promise<BitBoxSession> {
  return connectWith(connectNames[mode], params);
}
