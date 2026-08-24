// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { coinTypeFromNetwork } from '../networkUtils';
import { fromHex } from 'uint8array-tools';
import type {
  BitBoxSession,
  BitBoxApiNetwork,
  BitBoxSimpleType
} from './types';

type ApiXpubType = 'tpub' | 'xpub';

export function apiNetwork(session: BitBoxSession): BitBoxApiNetwork {
  const coinType = coinTypeFromNetwork(session.network);
  return coinType === 0 ? 'btc' : 'tbtc';
}

function xpubType(session: Pick<BitBoxSession, 'network'>): ApiXpubType {
  const coinType = coinTypeFromNetwork(session.network);
  return coinType === 0 ? 'xpub' : 'tpub';
}

export function simpleType(descriptorTemplate: string): BitBoxSimpleType {
  if (descriptorTemplate === 'pkh(@0/**)') {
    throw new Error(
      `BitBox02 does not support top-level legacy p2pkh descriptors; use shWpkh, wpkh, or tr`
    );
  }
  const name =
    descriptorTemplate === 'sh(wpkh(@0/**))'
      ? 'p2wpkhP2sh'
      : descriptorTemplate === 'wpkh(@0/**)'
        ? 'p2wpkh'
        : descriptorTemplate === 'tr(@0/**)'
          ? 'p2tr'
          : undefined;
  if (!name)
    throw new Error(
      `Descriptor template is not a BitBox02 supported simple type`
    );
  return name;
}

export async function getVersion({
  session
}: {
  session: BitBoxSession;
}): Promise<string> {
  return session.client.version();
}

export async function getMasterFingerprint({
  session
}: {
  session: BitBoxSession;
}): Promise<Uint8Array> {
  const { client, store } = session;
  if (store.masterFingerprint) return fromHex(store.masterFingerprint);

  const masterFingerprint = await client.rootFingerprint();
  store.masterFingerprint = masterFingerprint;
  return fromHex(masterFingerprint);
}

export async function getXpub({
  originPath,
  session,
  display = false
}: {
  originPath: string;
  session: BitBoxSession;
  display?: boolean;
}): Promise<string> {
  const { client, store } = session;
  if (!store.xpubs) store.xpubs = {};
  const cacheKey = `${originPath}:${xpubType(session)}`;
  let xpub = display ? undefined : store.xpubs[cacheKey];
  if (!xpub) {
    xpub = await client.btcXpub(
      apiNetwork(session),
      `m${originPath}`,
      xpubType(session),
      display
    );
    if (typeof xpub !== 'string' || xpub.length === 0)
      throw new Error(`BitBox returned an invalid xpub`);
    store.xpubs[cacheKey] = xpub;
  }
  return xpub;
}
