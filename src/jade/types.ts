// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { HWWPolicy } from '../hww/policies';
import type { Network } from '../networks';

export type JadeNetwork = 'mainnet' | 'testnet' | 'localtest';
export type JadeConnectionMode = 'usb' | 'ble' | 'tcp';
export type JadeSinglesigVariant =
  | 'pkh(k)'
  | 'sh(wpkh(k))'
  | 'wpkh(k)'
  | 'tr(k)';

export type JadeHttpRequest = {
  urls: readonly (string | { url?: string; onion?: string })[];
  method: string;
  accept?: string;
  data?: unknown;
};

export type JadeHttpRequestFunction = (
  request: JadeHttpRequest
) => Promise<{ body: unknown }>;

export type JadeDescriptorSummary = {
  descriptor_len: number;
  num_datavalues: number;
};

export type JadeRegisteredDescriptor = {
  descriptor_name: string;
  descriptor: string;
  datavalues: Record<string, string>;
};

export type JadeReceiveAddressOptions =
  | { variant: JadeSinglesigVariant; path: number[] }
  | { descriptorName: string; branch: number; pointer: number };

/** High-level Jade API supplied by a connection driver. */
export type JadeClient = {
  getVersionInfo(): Promise<Record<string, unknown>>;
  authUser(
    network: JadeNetwork,
    httpRequest?: JadeHttpRequestFunction
  ): Promise<boolean>;
  getMasterFingerprint(network: JadeNetwork): Promise<string>;
  getXpub(network: JadeNetwork, path: number[]): Promise<string>;
  getRegisteredDescriptors(): Promise<Record<string, JadeDescriptorSummary>>;
  getRegisteredDescriptor(name: string): Promise<JadeRegisteredDescriptor>;
  registerDescriptor(
    network: JadeNetwork,
    name: string,
    descriptor: string,
    datavalues: Record<string, string>
  ): Promise<boolean>;
  getReceiveAddress(
    network: JadeNetwork,
    options: JadeReceiveAddressOptions
  ): Promise<string>;
  signPSBT(network: JadeNetwork, psbt: Uint8Array): Promise<Uint8Array>;
  signMessage(path: number[], message: string): Promise<string | Uint8Array>;
};

export type ConnectedJadeClient = JadeClient & {
  disconnect(): void | Promise<void>;
};

export type JadeConnectOptions<TDevice> = {
  device?: TDevice;
  timeoutMs?: number;
};

type ConnectJade<TDevice> = (
  options?: JadeConnectOptions<TDevice>
) => Promise<ConnectedJadeClient>;

/** Driver module implemented by a Jade transport package. */
export type JadeDriverModule<TDevice = unknown> = {
  connectJadeUsb?: ConnectJade<TDevice>;
  connectJadeBle?: ConnectJade<TDevice>;
  connectJadeTcp?: ConnectJade<TDevice>;
};

/** JSON-safe Jade descriptor policy stored by the app. */
export type JadePolicy = HWWPolicy;

/** App-owned JSON store for cached Jade keys and descriptor policies. */
export type JadeStore = {
  masterFingerprint?: string;
  policies?: JadePolicy[];
  xpubs?: { [key: string]: string };
};

/** Connected Jade session. Persist the store, not the session. */
export type JadeSession = {
  client: JadeClient;
  store: JadeStore;
  network: Network;
  close(): Promise<void>;
};
