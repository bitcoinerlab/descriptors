// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { HWWPolicy } from '../hww/policies';
import type { Network } from '../networks';

export type BitBoxApiNetwork = 'btc' | 'tbtc';

export type BitBoxClient = {
  version(): string | Promise<string>;
  rootFingerprint(): string | Promise<string>;
  btcXpub(
    apiNetwork: BitBoxApiNetwork,
    keypath: BitBoxKeypath,
    xpubType: BitBoxXPubType,
    display: boolean
  ): Promise<string>;
  btcAddress(
    apiNetwork: BitBoxApiNetwork,
    keypath: BitBoxKeypath,
    scriptConfig: BitBoxScriptConfig,
    display: boolean
  ): Promise<string>;
  btcRegisterScriptConfig(
    apiNetwork: BitBoxApiNetwork,
    scriptConfig: BitBoxScriptConfig,
    keypathAccount: BitBoxKeypath | undefined,
    xpubType: BitBoxRegisterXPubType,
    name?: string
  ): Promise<void>;
  btcIsScriptConfigRegistered(
    apiNetwork: BitBoxApiNetwork,
    scriptConfig: BitBoxScriptConfig,
    keypathAccount?: BitBoxKeypath
  ): Promise<boolean>;
  btcSignPSBT(
    apiNetwork: BitBoxApiNetwork,
    psbt: string,
    forceScriptConfig: BitBoxScriptConfigWithKeypath | undefined,
    formatUnit: BitBoxFormatUnit
  ): Promise<string>;
  btcSignMessage?(
    apiNetwork: BitBoxApiNetwork,
    scriptConfig: BitBoxScriptConfigWithKeypath,
    message: Uint8Array
  ): Promise<{
    sig: Uint8Array;
    recid: bigint;
    electrumSig65: Uint8Array;
  }>;
};

export type BitBoxFormatUnit = 'default' | 'sat';
export type BitBoxXPubType =
  | 'tpub'
  | 'xpub'
  | 'ypub'
  | 'zpub'
  | 'vpub'
  | 'upub'
  | 'Vpub'
  | 'Zpub'
  | 'Upub'
  | 'Ypub';
export type BitBoxRegisterXPubType = 'autoElectrum' | 'autoXpubTpub';
export type BitBoxKeypath = string | number[];
export type BitBoxSimpleType = 'p2wpkhP2sh' | 'p2wpkh' | 'p2tr';
export type BitBoxMultisigScriptType = 'p2wsh' | 'p2wshP2sh';

export type BitBoxKeyOriginInfo = {
  rootFingerprint?: string;
  keypath?: BitBoxKeypath;
  xpub: string;
};

export type BitBoxPolicyScriptConfig = {
  policy: string;
  keys: BitBoxKeyOriginInfo[];
};

export type BitBoxScriptConfig =
  | { simpleType: BitBoxSimpleType }
  | { multisig: BitBoxMultisigScriptConfig }
  | { policy: BitBoxPolicyScriptConfig };

export type BitBoxScriptConfigWithKeypath = {
  scriptConfig: BitBoxScriptConfig;
  keypath: BitBoxKeypath;
};

export type BitBoxMultisigScriptConfig = {
  threshold: number;
  xpubs: string[];
  ourXpubIndex: number;
  scriptType: BitBoxMultisigScriptType;
};

/** JSON-safe BitBox descriptor policy stored by the app. */
export type BitBoxPolicy = HWWPolicy;

/**
 * App-owned BitBox store. This is plain JSON and should be persisted by the app.
 *
 * `masterFingerprint` is hex. `xpubs` are caches. `policies` is the local
 * hardware-wallet policy mapping needed to display addresses and sign later.
 * A BitBox can confirm whether a script config is registered, but it does not
 * return the app's descriptor policy list or a Ledger-style registration
 * receipt.
 */
export type BitBoxStore = {
  masterFingerprint?: string;
  policies?: BitBoxPolicy[];
  xpubs?: { [key: string]: string };
};

/** Connected BitBox session. Persist the store, not the session. */
export type BitBoxSession = {
  /** Connected and paired BitBox-compatible provider client. */
  client: BitBoxClient;
  /** App-owned JSON store. Persist this, not the session. */
  store: BitBoxStore;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Optional display unit passed to `btcSignPSBT`. */
  formatUnit?: BitBoxFormatUnit;
  /** Closes the client owned by this session. */
  close(): Promise<void>;
};
