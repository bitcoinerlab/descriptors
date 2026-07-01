// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';

export type KnownHardwareWalletKind =
  | 'bitbox02'
  | 'coldcard'
  | 'jade'
  | 'ledger'
  | 'passport-prime'
  | 'specter';

export type HardwareWalletKind = KnownHardwareWalletKind | (string & {});

export type WalletRegistration = {
  id?: Uint8Array;
  hmac?: Uint8Array;
};

export type WalletPolicy = {
  policyName?: string;
  descriptorTemplate: string;
  keyRoots: string[];
  registration?: WalletRegistration;
};

export type HardwareWalletState = {
  masterFingerprint?: Uint8Array;
  policies?: WalletPolicy[];
  xpubs?: { [key: string]: string };
};

export type HardwareWalletPolicyManager = {
  Output: OutputConstructor;
  network: Network;
  policies?: WalletPolicy[];
  getMasterFingerprint(): Promise<Uint8Array>;
  getXpub(originPath: string): Promise<string>;
};

export type HardwareWalletCapabilities = {
  directConnection: boolean;
  airgapped: boolean;
  walletPolicy: boolean;
  statelessRegistration: boolean;
  p2pkh: boolean;
  p2wpkh: boolean;
  p2shP2wpkh: boolean;
  p2wsh: boolean;
  taprootKeyPath: boolean;
  taprootScriptPath: boolean;
  miniscript: boolean;
};

export type DisplayAddressRequest =
  | {
      kind: 'path';
      path: string;
      addressFormat?: 'p2pkh' | 'p2wpkh' | 'p2sh-p2wpkh' | 'p2tr';
      display?: boolean;
    }
  | {
      kind: 'policy';
      policy: WalletPolicy;
      change: boolean;
      index: number;
      display?: boolean;
    };

export type SignPsbtRequest = {
  psbt: PsbtLike | ScureTransactionLike;
  policy?: WalletPolicy;
  inputIndexes?: number[];
};

export type SignedPsbtResult = {
  psbt?: PsbtLike | ScureTransactionLike;
  signedInputs?: number[];
};

export type HardwareWalletClient = {
  kind: HardwareWalletKind;
  getVersion(): Promise<string>;
  getMasterFingerprint(): Promise<Uint8Array>;
  getExtendedPubkey(
    path: string,
    options?: { display?: boolean }
  ): Promise<string>;
  registerWallet(params: {
    name: string;
    policy: WalletPolicy;
  }): Promise<WalletRegistration | undefined>;
  isWalletRegistered(params: {
    name: string;
    policy: WalletPolicy;
  }): Promise<boolean>;
  displayAddress(request: DisplayAddressRequest): Promise<string | void>;
  signPsbt(request: SignPsbtRequest): Promise<SignedPsbtResult>;
  getCapabilities?(): Promise<HardwareWalletCapabilities>;
};
