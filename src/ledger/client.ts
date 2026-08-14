// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { fromHex, toHex } from 'uint8array-tools';
import type {
  LedgerBitcoinApi,
  LedgerManager,
  LedgerPolicy,
  LedgerSession,
  LedgerStore
} from './types';

/**
 * Builds an internal session and migrates state for deprecated 3.x helpers.
 * The optional peer is loaded only if a policy helper uses `bitcoinApi`.
 *
 * @deprecated Remove with `LedgerManager` compatibility in v4.
 * @internal
 */
export function sessionFromLedgerManager(
  ledgerManager: LedgerManager
): LedgerSession {
  const state = ledgerManager.ledgerState;
  let bitcoinApi: LedgerBitcoinApi | undefined;
  if (state.masterFingerprint instanceof Uint8Array)
    state.masterFingerprint = toHex(state.masterFingerprint);
  if (state.policies?.some(policy => 'ledgerTemplate' in policy)) {
    state.policies = state.policies.map(policy => {
      if (!('ledgerTemplate' in policy)) return policy;
      const normalized: LedgerPolicy = {
        ...(policy.policyName !== undefined ? { name: policy.policyName } : {}),
        descriptorTemplate: policy.ledgerTemplate,
        keyRoots: policy.keyRoots,
        ...(policy.policyId !== undefined
          ? { policyId: toHex(policy.policyId) }
          : {}),
        ...(policy.policyHmac !== undefined
          ? { policyHmac: toHex(policy.policyHmac) }
          : {})
      };
      return normalized;
    });
  }
  return {
    client: ledgerManager.ledgerClient,
    // Load the policy API only when it is first needed, then reuse it.
    get bitcoinApi() {
      bitcoinApi ??= importLedgerBitcoinModule();
      return bitcoinApi;
    },
    store: state as LedgerStore,
    network: ledgerManager.network,
    // The deprecated manager keeps ownership of its existing transport.
    close: async () => undefined
  };
}

/**
 * Loads the optional Ledger Bitcoin peer for deprecated policy helpers.
 *
 * Modern sessions receive this module explicitly in `driver.bitcoinApi`.
 *
 * @deprecated Remove with `LedgerManager` compatibility in v4.
 * @internal
 */
export function importLedgerBitcoinModule(): LedgerBitcoinApi {
  let ledgerBitcoinModule: LedgerBitcoinApi;
  try {
    // Keep the optional Ledger peer out of module initialization for non-Ledger users.
    ledgerBitcoinModule =
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('@ledgerhq/ledger-bitcoin') as LedgerBitcoinApi;
  } catch (error) {
    void error;
    throw new Error(
      'Could not import "@ledgerhq/ledger-bitcoin". This peer dependency is required when using deprecated LedgerManager helpers. Please run "npm install @ledgerhq/ledger-bitcoin" or migrate to connect({ driver: { bitcoinApi } }).'
    );
  }
  return ledgerBitcoinModule;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function ledgerAppInfo(transport: any) {
  const r = await transport.send(0xb0, 0x01, 0x00, 0x00);
  let i = 0;
  const format = r[i++];
  const nameLength = r[i++];
  const name = String.fromCharCode(...r.slice(i, (i += nameLength!)));
  const versionLength = r[i++];
  const version = String.fromCharCode(...r.slice(i, (i += versionLength!)));
  const flagLength = r[i++];
  const flags = r.slice(i, (i += flagLength!));
  return { name, version, flags, format };
}

function parseVersionTriplet(version: string): [number, number, number] | null {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version);
  if (!match) return null;
  const triplet: [number, number, number] = [
    Number(match[1]),
    Number(match[2]),
    Number(match[3])
  ];
  return triplet.every(Number.isSafeInteger) ? triplet : null;
}

/**
 * Verifies if the Ledger device is connected, if the required Bitcoin App is opened,
 * and if the version of the app meets the minimum requirements.
 *
 * @throws Will throw an error if the Ledger device is not connected, the required
 * Bitcoin App is not opened, or if the version is below the required number.
 *
 * @returns Promise<void> - A promise that resolves if all assertions pass, or throws otherwise.
 */
export async function assertLedgerApp({
  transport,
  name,
  minVersion
}: {
  /**
   * Connection transport with the Ledger device.
   * One of these: https://github.com/LedgerHQ/ledger-live#libs---libraries
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transport: any;
  /**
   * The name of the Bitcoin App. "Bitcoin" for mainnet or "Bitcoin Test" for testnet.
   */
  name: string;
  /**
   * The minimum acceptable version of the Bitcoin App in semver format (major.minor.patch).
   */
  minVersion: string;
}): Promise<void> {
  const { name: openName, version } = await ledgerAppInfo(transport);
  if (openName !== name) {
    throw new Error(`Open the ${name} app and try again`);
  }
  const minimum = parseVersionTriplet(minVersion);
  if (!minimum)
    throw new Error(
      `Pass a minVersion using semver notation: major.minor.patch`
    );
  const current = parseVersionTriplet(version);
  if (!current)
    throw new Error(`Ledger returned an invalid app version: ${version}`);
  const [mVmajor, mVminor, mVpatch] = minimum;
  const [major, minor, patch] = current;
  if (
    major < mVmajor ||
    (major === mVmajor && minor < mVminor) ||
    (major === mVmajor && minor === mVminor && patch < mVpatch)
  )
    throw new Error(`Error: please upgrade ${name} to version ${minVersion}`);
}

export async function getMasterFingerprint({
  session
}: {
  session: LedgerSession;
}): Promise<Uint8Array> {
  const { client, store } = session;
  let masterFingerprint = store.masterFingerprint;
  if (!masterFingerprint) {
    masterFingerprint = await client.getMasterFingerprint();
    store.masterFingerprint = masterFingerprint;
  }
  return fromHex(masterFingerprint);
}

export async function getVersion({
  session
}: {
  session: LedgerSession;
}): Promise<string> {
  const { client } = session;
  const { version } = await client.getAppAndVersion();
  return version;
}

export async function getXpub({
  originPath,
  session
}: {
  originPath: string;
  session: LedgerSession;
}): Promise<string> {
  const { client, store } = session;
  if (!store.xpubs) store.xpubs = {};
  let xpub = store.xpubs[originPath];
  if (!xpub) {
    try {
      xpub = await client.getExtendedPubkey(`m${originPath}`, false);
    } catch (err) {
      void err;
      xpub = await client.getExtendedPubkey(`m${originPath}`, true);
    }
    if (typeof xpub !== 'string')
      throw new Error(`Error: Ledger client did not return a valid xpub`);
    store.xpubs[originPath] = xpub;
  }
  return xpub;
}

/**
 * Retrieves the master fingerprint of a Ledger device.
 *
 * @deprecated Use `getMasterFingerprint(...)` from the Ledger entrypoint
 * instead. Remove in v4 with `LedgerManager` compatibility.
 */
export async function getLedgerMasterFingerPrint({
  ledgerManager
}: {
  ledgerManager: LedgerManager;
}): Promise<Uint8Array> {
  return getMasterFingerprint({
    session: sessionFromLedgerManager(ledgerManager)
  });
}

/**
 * Retrieves the xpub for a given origin path from a Ledger device.
 *
 * @deprecated Use `getXpub(...)` from the Ledger entrypoint instead. Remove in
 * v4 with `LedgerManager` compatibility.
 */
export async function getLedgerXpub({
  originPath,
  ledgerManager
}: {
  originPath: string;
  ledgerManager: LedgerManager;
}): Promise<string> {
  return getXpub({
    originPath,
    session: sessionFromLedgerManager(ledgerManager)
  });
}
