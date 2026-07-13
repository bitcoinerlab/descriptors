// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Used only by the deprecated LedgerManager.Output field. Remove in v4.
import type { OutputConstructor } from '../descriptors';
import type { HWWPolicy } from '../hww/policies';
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

export type LedgerTransport = {
  send(cla: number, ins: number, p1: number, p2: number): Promise<Uint8Array>;
  close(): void | Promise<void>;
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

export type LedgerDefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';

/** Ledger Bitcoin app client and policy constructors supplied by the app. */
export type LedgerBitcoinApi<TTransport = LedgerTransport> = {
  AppClient: new (transport: TTransport) => LedgerClient;
  WalletPolicy: new (
    name: string,
    descriptorTemplate: string,
    keys: readonly string[]
  ) => LedgerWalletPolicyLike;
  DefaultWalletPolicy: new (
    descriptorTemplate: LedgerDefaultDescriptorTemplate,
    key: string
  ) => LedgerWalletPolicyLike;
};

export type LedgerWalletPolicyApi = Pick<
  LedgerBitcoinApi,
  'WalletPolicy' | 'DefaultWalletPolicy'
>;

/**
 * JSON-safe Ledger policy stored by the app.
 *
 * `policyId` and `policyHmac` are hex strings returned by Ledger when a
 * non-standard policy is registered.
 */
export type LedgerPolicy = HWWPolicy & {
  /** Hex-encoded Ledger policy id. */
  policyId?: string;
  /** Hex-encoded Ledger policy HMAC. Persist this to reuse the policy. */
  policyHmac?: string;
};

/**
 * App-owned Ledger store. This is plain JSON and should be persisted by the app.
 *
 * `masterFingerprint` is hex. `xpubs` are caches. `policies` stores Ledger
 * registration receipts so the app can reuse a registered policy.
 */
export type LedgerStore = {
  masterFingerprint?: string;
  policies?: LedgerPolicy[];
  xpubs?: { [key: string]: string };
};

/**
 * Persisted 3.x policy shape.
 *
 * @deprecated Remove with LedgerState migration in v4.
 * @internal
 */
type LegacyLedgerPolicy = {
  policyName?: string;
  ledgerTemplate: string;
  keyRoots: string[];
  policyId?: Uint8Array;
  policyHmac?: Uint8Array;
};

/**
 * @deprecated Use `Store` from the Ledger entrypoint for new integrations.
 * Remove in v4 with the deprecated `LedgerManager` helpers and legacy state
 * migration.
 *
 * Existing 3.x state is still accepted by deprecated `LedgerManager` helpers
 * and is migrated to the JSON-safe `LedgerStore` format in place.
 */
export type LedgerState = {
  masterFingerprint?: string | Uint8Array;
  policies?: (LedgerPolicy | LegacyLedgerPolicy)[];
  xpubs?: { [key: string]: string };
};

/** Connected Ledger session. Persist the store, not the session. */
export type LedgerSession = {
  /** Ledger Bitcoin app client instance. */
  client: LedgerClient;
  /** Ledger Bitcoin app API used to construct wallet policies. */
  bitcoinApi: LedgerWalletPolicyApi;
  /** App-owned JSON store. Persist this, not the session. */
  store: LedgerStore;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Closes the transport owned by this session. */
  close(): Promise<void>;
};

/**
 * @deprecated Use `Session` from the Ledger entrypoint. Remove in v4 with all
 * `LedgerManager` helpers and their backend compatibility plumbing.
 */
export type LedgerManager = {
  /** Ledger Bitcoin app client instance. */
  ledgerClient: LedgerClient;
  /** App-owned store for cached keys and registered Ledger policy receipts. */
  ledgerState: LedgerState;
  /**
   * @deprecated 3.x compatibility only. Deprecated policy helpers use this
   * backend-bound constructor. Remove this field and its type import in v4.
   */
  Output?: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
};
