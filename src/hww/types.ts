// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';

/**
 * Descriptor policy used by shared hardware-wallet helpers.
 *
 * `descriptorTemplate` is the device policy template, for example
 * `wsh(sortedmulti(2,@0/**,@1/**))`.
 *
 * `keyRoots` contains the xpub roots that replace `@0`, `@1`, and so on.
 * `name` is optional because standard policies and freshly derived policies do
 * not have a device registration name.
 */
export type HWWPolicy = {
  /** Human-readable policy name shown by the device when supported. */
  name?: string;
  /** Descriptor template with `@0`, `@1`, ... placeholders. */
  descriptorTemplate: string;
  /** Xpub roots used by the descriptor template placeholders. */
  keyRoots: string[];
};

/**
 * Small device-key interface used to build descriptor key expressions.
 *
 * Device adapters implement this by reading from their session and cache.
 */
export type HWWKeySource = {
  /** Master fingerprint of the connected hardware wallet. */
  getMasterFingerprint(): Promise<Uint8Array>;
  /** Account xpub for the origin path used in the descriptor key origin. */
  getAccountXpub(originPath: string): Promise<string>;
};

/**
 * Small adapter used by shared policy-matching code.
 *
 * It combines device keys, known policies, the Bitcoin network, and the bound
 * `Output` constructor needed to rebuild scripts from descriptors.
 */
export type HWWPolicyResolver = HWWKeySource & {
  /** Bound `Output` constructor from the selected backend package. */
  Output: OutputConstructor;
  /** Bitcoin network used to parse descriptors and standard account paths. */
  network: Network;
  /** Policies already known by the app or registered with the device. */
  knownPolicies?: HWWPolicy[];
};
