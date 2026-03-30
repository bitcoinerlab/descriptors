// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import * as ledgerBitcoinModule from '@ledgerhq/ledger-bitcoin';
import { fromHex } from 'uint8array-tools';
import type { LedgerManager } from './index';

export async function importAndValidateLedgerBitcoin(
  ledgerClient?: unknown
): Promise<unknown> {
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

/**
 * Retrieves the master fingerprint of a Ledger device.
 */
export async function getLedgerMasterFingerPrint({
  ledgerManager
}: {
  ledgerManager: LedgerManager;
}): Promise<Uint8Array> {
  const { ledgerClient, ledgerState } = ledgerManager;
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    ledgerClient
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);
  let masterFingerprint = ledgerState.masterFingerprint;
  if (!masterFingerprint) {
    masterFingerprint = fromHex(await ledgerClient.getMasterFingerprint());
    ledgerState.masterFingerprint = masterFingerprint;
  }
  return masterFingerprint;
}

/**
 * Retrieves the xpub for a given origin path from a Ledger device.
 */
export async function getLedgerXpub({
  originPath,
  ledgerManager
}: {
  originPath: string;
  ledgerManager: LedgerManager;
}): Promise<string> {
  const { ledgerClient, ledgerState } = ledgerManager;
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    ledgerClient
  )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);
  if (!ledgerState.xpubs) ledgerState.xpubs = {};
  let xpub = ledgerState.xpubs[originPath];
  if (!xpub) {
    try {
      xpub = await ledgerClient.getExtendedPubkey(`m${originPath}`, false);
    } catch (err) {
      void err;
      xpub = await ledgerClient.getExtendedPubkey(`m${originPath}`, true);
    }
    if (typeof xpub !== 'string')
      throw new Error(`Error: ledgerClient did not return a valid xpub`);
    ledgerState.xpubs[originPath] = xpub;
  }
  return xpub;
}
