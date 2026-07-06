// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { fromHex } from 'uint8array-tools';
import type { LedgerManager, LedgerSession } from './types';

type LedgerBitcoinModule = typeof import('@ledgerhq/ledger-bitcoin');

export async function importAndValidateLedgerBitcoin(
  ledgerClient?: unknown
): Promise<unknown> {
  let ledgerBitcoinModule: LedgerBitcoinModule;
  try {
    // Keep the optional Ledger peer out of module initialization for non-Ledger users.
    ledgerBitcoinModule =
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require('@ledgerhq/ledger-bitcoin') as LedgerBitcoinModule;
  } catch (error) {
    void error;
    throw new Error(
      'Could not import "@ledgerhq/ledger-bitcoin". This peer dependency is required when using Ledger helpers. Please run "npm install @ledgerhq/ledger-bitcoin" or import only non-Ledger APIs.'
    );
  }
  const { AppClient } = ledgerBitcoinModule;
  if (ledgerClient !== undefined && !(ledgerClient instanceof AppClient)) {
    throw new Error('Error: invalid AppClient instance');
  }
  return ledgerBitcoinModule;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function ledgerAppInfo(transport: any) {
  const r = await transport.send(0xb0, 0x01, 0x00, 0x00);
  let i = 0;
  const format = r[i++];
  const nameLength = r[i++];
  const name = r.slice(i, (i += nameLength!)).toString('ascii');
  const versionLength = r[i++];
  const version = r.slice(i, (i += versionLength!)).toString('ascii');
  const flagLength = r[i++];
  const flags = r.slice(i, (i += flagLength!));
  return { name, version, flags, format };
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
  } else {
    const [mVmajor, mVminor, mVpatch] = minVersion.split('.').map(Number);
    const [major, minor, patch] = version.split('.').map(Number);
    if (
      mVmajor === undefined ||
      mVminor === undefined ||
      mVpatch === undefined
    ) {
      throw new Error(
        `Pass a minVersion using semver notation: major.minor.patch`
      );
    }
    if (
      major < mVmajor ||
      (major === mVmajor && minor < mVminor) ||
      (major === mVmajor && minor === mVminor && patch < mVpatch)
    )
      throw new Error(`Error: please upgrade ${name} to version ${minVersion}`);
  }
}

export async function getMasterFingerprint({
  session
}: {
  session: LedgerSession;
}): Promise<Uint8Array> {
  const { client, state } = session;
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    client
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
  let masterFingerprint = state.masterFingerprint;
  if (!masterFingerprint) {
    masterFingerprint = fromHex(await client.getMasterFingerprint());
    state.masterFingerprint = masterFingerprint;
  }
  return masterFingerprint;
}

export async function getVersion({
  session
}: {
  session: LedgerSession;
}): Promise<string> {
  const { client } = session;
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    client
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
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
  const { client, state } = session;
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    client
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(client instanceof AppClient))
    throw new Error(`Error: pass a valid Ledger client`);
  if (!state.xpubs) state.xpubs = {};
  let xpub = state.xpubs[originPath];
  if (!xpub) {
    try {
      xpub = await client.getExtendedPubkey(`m${originPath}`, false);
    } catch (err) {
      void err;
      xpub = await client.getExtendedPubkey(`m${originPath}`, true);
    }
    if (typeof xpub !== 'string')
      throw new Error(`Error: Ledger client did not return a valid xpub`);
    state.xpubs[originPath] = xpub;
  }
  return xpub;
}

/**
 * Retrieves the master fingerprint of a Ledger device.
 *
 * @deprecated Use `getMasterFingerprint(...)` from the Ledger entrypoint instead.
 */
export async function getLedgerMasterFingerPrint({
  ledgerManager
}: {
  ledgerManager: LedgerManager;
}): Promise<Uint8Array> {
  return getMasterFingerprint({
    session: {
      client: ledgerManager.ledgerClient,
      state: ledgerManager.ledgerState,
      Output: ledgerManager.Output,
      network: ledgerManager.network
    }
  });
}

/**
 * Retrieves the xpub for a given origin path from a Ledger device.
 *
 * @deprecated Use `getXpub(...)` from the Ledger entrypoint instead.
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
    session: {
      client: ledgerManager.ledgerClient,
      state: ledgerManager.ledgerState,
      Output: ledgerManager.Output,
      network: ledgerManager.network
    }
  });
}
