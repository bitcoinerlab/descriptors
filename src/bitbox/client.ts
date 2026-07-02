// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { coinTypeFromNetwork } from '../networkUtils';
import type {
  BitBoxFormatUnit,
  BitBoxManager,
  BitBoxApiNetwork,
  BitBoxRegisterXPubType,
  BitBoxSimpleType,
  BitBoxXPubType
} from './types';
import { bitboxKeypathFromString, normalizeFingerprint } from './utils';

export function bitboxApiNetwork(
  bitboxManager: BitBoxManager
): BitBoxApiNetwork {
  const coinType = coinTypeFromNetwork(bitboxManager.network);
  return coinType === 0 ? 'btc' : 'tbtc';
}

export function bitboxXpubType(bitboxManager: BitBoxManager): BitBoxXPubType {
  if (bitboxManager.xpubType !== undefined) return bitboxManager.xpubType;
  const coinType = coinTypeFromNetwork(bitboxManager.network);
  return coinType === 0 ? 'xpub' : 'tpub';
}

export function bitboxRegisterXpubType(
  bitboxManager: BitBoxManager
): BitBoxRegisterXPubType {
  return bitboxManager.registerXpubType ?? 'autoXpubTpub';
}

export function bitboxFormatUnit(
  bitboxManager: BitBoxManager
): BitBoxFormatUnit {
  return bitboxManager.formatUnit ?? 'default';
}

export function bitboxSimpleType({
  descriptorTemplate,
  bitboxManager
}: {
  descriptorTemplate: string;
  bitboxManager: BitBoxManager;
}): BitBoxSimpleType {
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
  void bitboxManager;
  return name;
}

export async function getBitBoxVersion({
  bitboxManager
}: {
  bitboxManager: BitBoxManager;
}): Promise<string> {
  return bitboxManager.bitboxClient.version();
}

export async function getBitBoxMasterFingerprint({
  bitboxManager
}: {
  bitboxManager: BitBoxManager;
}): Promise<Uint8Array> {
  const { bitboxClient, bitboxState } = bitboxManager;
  if (bitboxState.masterFingerprint) return bitboxState.masterFingerprint;

  const fingerprintSource = await bitboxClient.rootFingerprint();

  const masterFingerprint = normalizeFingerprint(fingerprintSource);
  bitboxState.masterFingerprint = masterFingerprint;
  return masterFingerprint;
}

export async function getBitBoxXpub({
  originPath,
  bitboxManager,
  display = false
}: {
  originPath: string;
  bitboxManager: BitBoxManager;
  display?: boolean;
}): Promise<string> {
  const { bitboxClient, bitboxState } = bitboxManager;
  if (!bitboxState.xpubs) bitboxState.xpubs = {};
  const cacheKey = `${originPath}:${String(bitboxXpubType(bitboxManager))}`;
  let xpub = bitboxState.xpubs[cacheKey];
  if (!xpub) {
    xpub = await bitboxClient.btcXpub(
      bitboxApiNetwork(bitboxManager),
      bitboxKeypathFromString(originPath),
      bitboxXpubType(bitboxManager),
      display
    );
    bitboxState.xpubs[cacheKey] = xpub;
  }
  return xpub;
}
