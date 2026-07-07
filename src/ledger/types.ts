// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';

export type LedgerPartialSignature = {
  readonly pubkey: Uint8Array;
  readonly signature: Uint8Array;
  readonly tapleafHash?: Uint8Array;
};

export type LedgerWalletPolicyLike = {
  readonly name: string;
  readonly descriptorTemplate: string;
  readonly keys: readonly string[];
  getId(): Uint8Array;
  serialize(): Uint8Array;
};

export type LedgerClient = {
  getAppAndVersion(): Promise<{
    name: string;
    version: string;
    flags: number | Uint8Array;
  }>;
  getMasterFingerprint(): Promise<string>;
  getExtendedPubkey(path: string, display?: boolean): Promise<string>;
  registerWallet(
    walletPolicy: LedgerWalletPolicyLike
  ): Promise<readonly [Uint8Array, Uint8Array]>;
  getWalletAddress(
    walletPolicy: LedgerWalletPolicyLike,
    walletHMAC: Uint8Array | null,
    change: number,
    addressIndex: number,
    display: boolean
  ): Promise<string>;
  signPsbt(
    psbt: string,
    walletPolicy: LedgerWalletPolicyLike,
    walletHMAC: Uint8Array | null,
    progressCallback?: () => void
  ): Promise<[number, LedgerPartialSignature][]>;
  signMessage?(message: Uint8Array, path: string): Promise<string>;
};

export type LedgerPolicy = {
  name?: string;
  descriptorTemplate: string;
  keyRoots: string[];
  /** Hex-encoded Ledger policy id. */
  policyId?: string;
  /** Hex-encoded Ledger policy HMAC. Persist this to reuse the policy. */
  policyHmac?: string;
};

/**
 * App-owned Ledger store. This is plain JSON and should be persisted by the app.
 *
 * `masterFingerprint` is hex. `xpubs` are caches. `policies` stores Ledger
 * wallet policy registration receipts so the app can reuse a registered policy.
 */
export type LedgerStore = {
  masterFingerprint?: string;
  policies?: LedgerPolicy[];
  xpubs?: { [key: string]: string };
};

/** @deprecated Use `LedgerStore`. */
export type LedgerState = LedgerStore;

/**
 * Connected Ledger session plus the descriptor backend needed by this package.
 */
export type LedgerSession = {
  /** Ledger Bitcoin app client instance. */
  client: LedgerClient;
  /** App-owned JSON store. Persist this, not the session. */
  store: LedgerStore;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
};

/**
 * @deprecated Use `LedgerSession`.
 */
export type LedgerManager = {
  /** Ledger Bitcoin app client instance. */
  ledgerClient: LedgerClient;
  /** App-owned store for cached keys and registered wallet policy receipts. */
  ledgerState: LedgerStore;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
};
