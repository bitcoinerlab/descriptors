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
  keypathAccount: number[];
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

export type BitBoxState = {
  masterFingerprint?: Uint8Array;
  policies?: BitBoxPolicy[];
  xpubs?: { [key: string]: string };
};

export type BitBoxManager = {
  /** Connected and paired BitBox API client, for example `PairedBitBox` from `bitbox-api`. */
  bitboxClient: BitBoxClient;
  /** Mutable cache for fingerprint, xpubs and registered policies. */
  bitboxState: BitBoxState;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Optional xpub type override passed to `btcXpub`. */
  xpubType?: BitBoxXPubType;
  /** Optional registration xpub mode override passed to `btcRegisterScriptConfig`. */
  registerXpubType?: BitBoxRegisterXPubType;
  /** Optional display unit passed to `btcSignPSBT`. */
  formatUnit?: BitBoxFormatUnit;
};
