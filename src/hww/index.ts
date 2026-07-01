/**
 * Transport-free hardware wallet helpers shared by device adapters.
 *
 * This module intentionally contains no HID, serial, BLE, WebHID, or React
 * Native transport code. Device adapters should map their I/O layer onto these
 * policy and PSBT primitives.
 *
 * @module hww
 */

// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

export type {
  DisplayAddressRequest,
  HardwareWalletCapabilities,
  HardwareWalletClient,
  HardwareWalletKind,
  HardwareWalletPolicyManager,
  HardwareWalletState,
  KnownHardwareWalletKind,
  SignedPsbtResult,
  SignPsbtRequest,
  WalletPolicy,
  WalletRegistration
} from './types';

export { keyExpressionHardwareWallet } from './keyExpressions';
export * as policies from './policies';
