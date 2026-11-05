// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { fromHex } from 'uint8array-tools';
import { isBitcoinMainnet } from '../networkUtils';
import type { Network } from '../networks';
import type { JadeNetwork, JadeSession, JadeSinglesigVariant } from './types';

export function jadeNetwork(network: Network): JadeNetwork {
  if (isBitcoinMainnet(network)) return 'mainnet';
  return network.bech32 === 'bcrt' ? 'localtest' : 'testnet';
}

export function jadePath(path: string): number[] {
  const normalized = path.replaceAll('H', "'").replaceAll('h', "'");
  if (normalized === '' || normalized === 'm') return [];
  if (!/^(?:m)?(?:\/\d+'?)+$/.test(normalized))
    throw new Error(`Invalid BIP32 path: ${path}`);

  return normalized
    .replace(/^m/, '')
    .slice(1)
    .split('/')
    .map(element => {
      const hardened = element.endsWith("'");
      const value = Number(hardened ? element.slice(0, -1) : element);
      if (!Number.isSafeInteger(value) || value < 0 || value >= 0x80000000)
        throw new Error(`BIP32 path element overflow: ${element}`);
      return hardened ? value + 0x80000000 : value;
    });
}

export function singlesigVariant(
  descriptorTemplate: string
): JadeSinglesigVariant {
  const variant =
    descriptorTemplate === 'pkh(@0/**)'
      ? 'pkh(k)'
      : descriptorTemplate === 'sh(wpkh(@0/**))'
        ? 'sh(wpkh(k))'
        : descriptorTemplate === 'wpkh(@0/**)'
          ? 'wpkh(k)'
          : descriptorTemplate === 'tr(@0/**)'
            ? 'tr(k)'
            : undefined;
  if (!variant)
    throw new Error(`Descriptor template is not a Jade singlesig type`);
  return variant;
}

export async function getVersion({
  session
}: {
  session: JadeSession;
}): Promise<string> {
  const info = await session.client.getVersionInfo();
  const version = info['JADE_VERSION'];
  if (typeof version !== 'string' || version.length === 0)
    throw new Error(`Jade returned an invalid firmware version`);
  return version;
}

export async function getMasterFingerprint({
  session
}: {
  session: JadeSession;
}): Promise<Uint8Array> {
  const { client, store } = session;
  let masterFingerprint = store.masterFingerprint;
  if (!masterFingerprint) {
    masterFingerprint = (
      await client.getMasterFingerprint(jadeNetwork(session.network))
    ).toLowerCase();
    if (!/^[0-9a-f]{8}$/.test(masterFingerprint))
      throw new Error(`Jade returned an invalid master fingerprint`);
    store.masterFingerprint = masterFingerprint;
  }
  return fromHex(masterFingerprint);
}

export async function getXpub({
  originPath,
  session
}: {
  originPath: string;
  session: JadeSession;
}): Promise<string> {
  const { client, store } = session;
  if (!store.xpubs) store.xpubs = {};
  const apiNetwork = jadeNetwork(session.network);
  const cacheKey = `${originPath}:${apiNetwork}`;
  let xpub = store.xpubs[cacheKey];
  if (!xpub) {
    xpub = await client.getXpub(apiNetwork, jadePath(originPath));
    if (typeof xpub !== 'string' || xpub.length === 0)
      throw new Error(`Jade returned an invalid xpub`);
    store.xpubs[cacheKey] = xpub;
  }
  return xpub;
}
