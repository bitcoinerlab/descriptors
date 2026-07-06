// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import type {
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxSession,
  BitBoxState
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

const importBitBoxApi = new Function(
  'specifier',
  'return import(specifier)'
) as (specifier: string) => Promise<BitBoxApiModule>;

export type FromClientParams = {
  /** Connected and paired BitBox-compatible provider client. */
  client: BitBoxClient;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Existing app-owned state for cached keys and wallet policy metadata. */
  state?: BitBoxState;
  /** Optional display unit passed to `btcSignPSBT`. */
  formatUnit?: BitBoxFormatUnit;
};

export function fromClient({
  client,
  Output,
  network,
  state,
  formatUnit
}: FromClientParams): BitBoxSession {
  const session: BitBoxSession = {
    client,
    state: state ?? {},
    Output,
    network
  };
  if (formatUnit !== undefined) session.formatUnit = formatUnit;
  return session;
}

export type ConnectMechanism = 'auto' | 'bridge' | 'webhid';

export type ConnectParams = Omit<FromClientParams, 'client'> & {
  /** Called when bitbox-api reports that the device connection closed. */
  onClose?: () => void;
  /** Called with the pairing code before waiting for device confirmation. */
  onPairingCode?: (pairingCode: string) => void | Promise<void>;
};

async function connectWith(
  connectName: keyof Pick<
    BitBoxApiModule,
    'bitbox02ConnectAuto' | 'bitbox02ConnectBridge' | 'bitbox02ConnectWebHID'
  >,
  params: ConnectParams
): Promise<BitBoxSession> {
  const bitboxApi = await importBitBoxApi('bitbox-api');
  const unpaired = await bitboxApi[connectName](params.onClose);
  const pairing = await unpaired.unlockAndPair();
  const pairingCode = pairing.getPairingCode();
  if (pairingCode !== undefined) await params.onPairingCode?.(pairingCode);
  const client = await pairing.waitConfirm();

  return fromClient({
    client,
    Output: params.Output,
    network: params.network,
    ...(params.state !== undefined ? { state: params.state } : {}),
    ...(params.formatUnit !== undefined
      ? { formatUnit: params.formatUnit }
      : {})
  });
}

export function auto(params: ConnectParams): Promise<BitBoxSession> {
  return connectWith('bitbox02ConnectAuto', params);
}

export function bridge(params: ConnectParams): Promise<BitBoxSession> {
  return connectWith('bitbox02ConnectBridge', params);
}

export function webhid(params: ConnectParams): Promise<BitBoxSession> {
  return connectWith('bitbox02ConnectWebHID', params);
}

export async function connect({
  mechanism = 'auto',
  ...params
}: ConnectParams & { mechanism?: ConnectMechanism }): Promise<BitBoxSession> {
  if (mechanism === 'bridge') return bridge(params);
  if (mechanism === 'webhid') return webhid(params);
  return auto(params);
}
