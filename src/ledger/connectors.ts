// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import { assertLedgerApp, importAndValidateLedgerBitcoin } from './client';
import type { LedgerClient, LedgerSession, LedgerState } from './types';

type LedgerTransport = {
  send(cla: number, ins: number, p1: number, p2: number): Promise<Uint8Array>;
};

type LedgerNodeHidTransportModule = {
  default: {
    create(
      openTimeout?: number,
      listenTimeout?: number
    ): Promise<LedgerTransport>;
  };
};

const importModule = new Function('specifier', 'return import(specifier)') as (
  specifier: string
) => Promise<unknown>;

export type FromClientParams = {
  /** Ledger Bitcoin app client instance. */
  client: LedgerClient;
  /** Pre-bound `Output` constructor from the package/backend you are using. */
  Output: OutputConstructor;
  /** Bitcoin network used for descriptor and policy interpretation. */
  network: Network;
  /** Existing app-owned state for cached keys and wallet policy receipts. */
  state?: LedgerState;
};

export function fromClient({
  client,
  Output,
  network,
  state
}: FromClientParams): LedgerSession {
  return {
    client,
    state: state ?? {},
    Output,
    network
  };
}

export type NodeHidParams = Omit<FromClientParams, 'client'> & {
  /** Timeout in milliseconds while opening the HID transport. */
  openTimeout?: number;
  /** Timeout in milliseconds for HID exchanges. */
  listenTimeout?: number;
  /** Expected open Ledger app name. */
  appName?: string;
  /** Minimum acceptable Bitcoin app version. */
  minVersion?: string;
  /** Set to false if the caller validates the app separately. */
  assertApp?: boolean;
};

export async function nodeHid({
  Output,
  network,
  state,
  openTimeout = 3000,
  listenTimeout = 3000,
  appName = 'Bitcoin',
  minVersion = '2.1.0',
  assertApp = true
}: NodeHidParams): Promise<LedgerSession> {
  const transportModule = (await importModule(
    '@ledgerhq/hw-transport-node-hid'
  )) as LedgerNodeHidTransportModule;
  const ledgerBitcoin =
    (await importAndValidateLedgerBitcoin()) as typeof import('@ledgerhq/ledger-bitcoin');

  const transport = await transportModule.default.create(
    openTimeout,
    listenTimeout
  );
  if (assertApp)
    await assertLedgerApp({ transport, name: appName, minVersion });

  return fromClient({
    client: new ledgerBitcoin.AppClient(
      transport as ConstructorParameters<typeof ledgerBitcoin.AppClient>[0]
    ),
    Output,
    network,
    ...(state !== undefined ? { state } : {})
  });
}
