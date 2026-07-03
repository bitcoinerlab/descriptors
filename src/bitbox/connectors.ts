// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import type { BitBoxApiXPubType } from './client';
import type {
  BitBoxApiNetwork,
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxKeypath,
  BitBoxManager,
  BitBoxScriptConfig,
  BitBoxState
} from './types';

type BitBoxConnection = {
  unlockAndPair(): Promise<BitBoxPairing>;
};

type BitBoxPairing = {
  getPairingCode(): string | undefined;
  waitConfirm(): Promise<RawBitBoxApiClient>;
};

type RawBitBoxApiClient = Omit<
  BitBoxClient,
  'btcXpub' | 'btcRegisterScriptConfig'
> & {
  btcXpub(
    apiNetwork: BitBoxApiNetwork,
    keypath: BitBoxKeypath,
    xpubType: BitBoxApiXPubType,
    display: boolean
  ): Promise<string>;
  btcRegisterScriptConfig(
    apiNetwork: BitBoxApiNetwork,
    scriptConfig: BitBoxScriptConfig,
    keypathAccount: BitBoxKeypath | undefined,
    xpubType: 'autoXpubTpub',
    name?: string
  ): Promise<void>;
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
  /** Connected and paired descriptor-native BitBox client. */
  client: BitBoxClient;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Existing mutable cache for fingerprint, xpubs and registered policies. */
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
}: FromClientParams): BitBoxManager {
  const manager: BitBoxManager = {
    bitboxClient: client,
    bitboxState: state ?? {},
    Output,
    network
  };
  if (formatUnit !== undefined) manager.formatUnit = formatUnit;
  return manager;
}

export type FromBitBoxApiClientParams = Omit<FromClientParams, 'client'> & {
  /** Connected and paired client with the raw `bitbox-api` method shape. */
  client: RawBitBoxApiClient;
};

function bitboxXpubTypeFromApiNetwork(
  apiNetwork: BitBoxApiNetwork
): BitBoxApiXPubType {
  return apiNetwork === 'btc' ? 'xpub' : 'tpub';
}

/**
 * Wraps a raw `bitbox-api` client so the rest of this module can use the
 * smaller descriptor-native BitBox client shape.
 */
function adaptRawBitBoxApiClient(client: RawBitBoxApiClient): BitBoxClient {
  return {
    version: () => client.version(),
    rootFingerprint: () => client.rootFingerprint(),
    btcXpub: (apiNetwork, keypath, display) =>
      client.btcXpub(
        apiNetwork,
        keypath,
        bitboxXpubTypeFromApiNetwork(apiNetwork),
        display
      ),
    btcAddress: (apiNetwork, keypath, scriptConfig, display) =>
      client.btcAddress(apiNetwork, keypath, scriptConfig, display),
    btcRegisterScriptConfig: (apiNetwork, scriptConfig, keypathAccount, name) =>
      client.btcRegisterScriptConfig(
        apiNetwork,
        scriptConfig,
        keypathAccount,
        'autoXpubTpub',
        name
      ),
    btcIsScriptConfigRegistered: (apiNetwork, scriptConfig, keypathAccount) =>
      client.btcIsScriptConfigRegistered(
        apiNetwork,
        scriptConfig,
        keypathAccount
      ),
    btcSignPSBT: (apiNetwork, psbt, forceScriptConfig, formatUnit) =>
      client.btcSignPSBT(apiNetwork, psbt, forceScriptConfig, formatUnit)
  };
}

export function fromBitBoxApiClient({
  client,
  Output,
  network,
  state,
  formatUnit
}: FromBitBoxApiClientParams): BitBoxManager {
  return fromClient({
    client: adaptRawBitBoxApiClient(client),
    Output,
    network,
    ...(state !== undefined ? { state } : {}),
    ...(formatUnit !== undefined ? { formatUnit } : {})
  });
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
): Promise<BitBoxManager> {
  const bitboxApi = await importBitBoxApi('bitbox-api');
  const unpaired = await bitboxApi[connectName](params.onClose);
  const pairing = await unpaired.unlockAndPair();
  const pairingCode = pairing.getPairingCode();
  if (pairingCode !== undefined) await params.onPairingCode?.(pairingCode);
  const client = await pairing.waitConfirm();

  return fromBitBoxApiClient({
    client,
    Output: params.Output,
    network: params.network,
    ...(params.state !== undefined ? { state: params.state } : {}),
    ...(params.formatUnit !== undefined
      ? { formatUnit: params.formatUnit }
      : {})
  });
}

export function auto(params: ConnectParams): Promise<BitBoxManager> {
  return connectWith('bitbox02ConnectAuto', params);
}

export function bridge(params: ConnectParams): Promise<BitBoxManager> {
  return connectWith('bitbox02ConnectBridge', params);
}

export function webhid(params: ConnectParams): Promise<BitBoxManager> {
  return connectWith('bitbox02ConnectWebHID', params);
}

export async function connect({
  mechanism = 'auto',
  ...params
}: ConnectParams & { mechanism?: ConnectMechanism }): Promise<BitBoxManager> {
  if (mechanism === 'bridge') return bridge(params);
  if (mechanism === 'webhid') return webhid(params);
  return auto(params);
}
