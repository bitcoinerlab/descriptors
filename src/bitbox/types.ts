// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
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

export type BitBoxMultisigAccount = {
  keypathAccount: string;
  threshold: number;
  xpubs: string[];
  ourXpubIndex: number;
  scriptType: BitBoxMultisigScriptType;
};

export type BitBoxPolicy = {
  policyName?: string;
  descriptorTemplate: string;
  keyRoots: string[];
  account?: BitBoxMultisigAccount;
};

/**
 * App-owned BitBox state.
 *
 * `masterFingerprint` and `xpubs` are caches. `policies` is the local wallet
 * policy mapping this library needs to display addresses and sign later. A
 * BitBox can confirm whether a script config is registered, but it does not
 * return the app's descriptor policy list.
 */
export type BitBoxState = {
  masterFingerprint?: Uint8Array;
  policies?: BitBoxPolicy[];
  xpubs?: { [key: string]: string };
};

export type BitBoxSession = {
  /** Connected and paired BitBox-compatible provider client. */
  client: BitBoxClient;
  /** App-owned state for cached keys and registered wallet policy metadata. */
  state: BitBoxState;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Optional display unit passed to `btcSignPSBT`. */
  formatUnit?: BitBoxFormatUnit;
};
