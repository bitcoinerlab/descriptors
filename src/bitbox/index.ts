/**
 * BitBox helpers shared by both preset packages.
 *
 * This entrypoint does not import `bitbox-api` directly. Pass a connected and
 * paired BitBox client from whichever transport/runtime integration your app
 * uses.
 *
 * @module bitbox
 */

// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { OutputConstructor } from '../descriptors';
import type { Network } from '../networks';
import {
  bitboxPolicyFromStandard,
  bitboxPolicyFromState,
  bitboxAddressKeypathFromPolicy,
  bitboxScriptConfigFromMultisigAccount,
  bitboxScriptConfigFromPolicy,
  registerBitBoxWallet
} from './policies';
import {
  bitboxApiNetwork,
  bitboxSimpleType,
  getBitBoxMasterFingerprint,
  getBitBoxVersion,
  getBitBoxXpub
} from './client';
import { keyExpressionBitBox } from './keyExpressions';
import { bitboxKeypathFromString } from './utils';
import type { BitBoxManager, BitBoxPolicy, BitBoxState } from './types';

export type {
  BitBoxClient,
  BitBoxFormatUnit,
  BitBoxKeyOriginInfo,
  BitBoxKeypath,
  BitBoxManager,
  BitBoxMultisigAccount,
  BitBoxMultisigScriptConfig,
  BitBoxMultisigScriptType,
  BitBoxPolicy,
  BitBoxPolicyScriptConfig,
  BitBoxRegisterXPubType,
  BitBoxScriptConfig,
  BitBoxScriptConfigWithKeypath,
  BitBoxSimpleType,
  BitBoxState
} from './types';

export {
  bitboxAccountFromPolicy,
  bitboxPolicyFromOutput,
  bitboxPolicyFromPsbtInput,
  bitboxPolicyFromStandard,
  bitboxPolicyFromState,
  bitboxAddressKeypathFromPolicy,
  bitboxOwnOriginPathFromPolicy,
  bitboxSigningKeypathFromPolicy,
  bitboxScriptConfigFromMultisigAccount,
  bitboxScriptConfigFromPolicy,
  fingerprintHex,
  registerBitBoxWallet
} from './policies';
export {
  getBitBoxMasterFingerprint,
  getBitBoxVersion,
  getBitBoxXpub
} from './client';
export { keyExpressionBitBox };
export { bitboxKeypathFromString } from './utils';
export * as scriptExpressions from './scriptExpressions';
export * as signers from './signers';
export * as connectors from './connectors';

export type Manager = BitBoxManager;
export type State = BitBoxState;

export async function getVersion({
  manager
}: {
  manager: BitBoxManager;
}): Promise<string> {
  return getBitBoxVersion({ bitboxManager: manager });
}

export async function getMasterFingerprint({
  manager
}: {
  manager: BitBoxManager;
}): Promise<Uint8Array> {
  return getBitBoxMasterFingerprint({ bitboxManager: manager });
}

export async function getXpub({
  manager,
  originPath,
  display
}: {
  manager: BitBoxManager;
  originPath: string;
  display?: boolean;
}): Promise<string> {
  return getBitBoxXpub({
    bitboxManager: manager,
    originPath,
    ...(display !== undefined ? { display } : {})
  });
}

export async function keyExpression({
  manager,
  originPath,
  keyPath,
  change,
  index
}: {
  manager: BitBoxManager;
  originPath: string;
  change?: number | undefined;
  index?: number | undefined | '*';
  keyPath?: string | undefined;
}): Promise<string> {
  return keyExpressionBitBox({
    bitboxManager: manager,
    originPath,
    keyPath,
    change,
    index
  });
}

export async function registerWallet({
  descriptor,
  manager,
  policyName
}: {
  descriptor: string;
  manager: BitBoxManager;
  policyName: string;
}): Promise<void> {
  return registerBitBoxWallet({
    descriptor,
    bitboxManager: manager,
    policyName
  });
}

export type BitBoxAddressDisplayParams = {
  descriptor: string;
  bitboxManager: BitBoxManager;
  change?: number;
  index: number;
};

function outputForDisplay({
  descriptor,
  bitboxManager,
  change,
  index
}: BitBoxAddressDisplayParams) {
  const { Output, network } = bitboxManager;
  return new Output({
    descriptor,
    ...(descriptor.includes('*') ? { index } : {}),
    ...(change !== undefined ? { change } : {}),
    network
  });
}

function keyRootOriginPath(keyRoot: string): string | undefined {
  return keyRoot.match(/^\[[0-9a-fA-F]{8}([^\]]*)\]/)?.[1];
}

async function displayStandardAddress({
  policy,
  bitboxManager,
  change,
  index
}: {
  policy: BitBoxPolicy;
  bitboxManager: BitBoxManager;
  change: number;
  index: number;
}) {
  const { bitboxClient } = bitboxManager;
  const originPath = keyRootOriginPath(policy.keyRoots[0] ?? '');
  if (!originPath) throw new Error(`BitBox02 key root missing origin path`);
  return bitboxClient.btcAddress(
    bitboxApiNetwork(bitboxManager),
    bitboxKeypathFromString(`${originPath}/${change}/${index}`),
    {
      simpleType: bitboxSimpleType({
        descriptorTemplate: policy.descriptorTemplate,
        bitboxManager
      })
    },
    true
  );
}

async function displayMultisigAddress({
  policy,
  bitboxManager,
  change,
  index
}: {
  policy: BitBoxPolicy;
  bitboxManager: BitBoxManager;
  change: number;
  index: number;
}) {
  const { bitboxClient } = bitboxManager;
  const account = policy.account;
  if (!account)
    throw new Error(
      `BitBox policy missing account; call registerBitBoxWallet first`
    );
  return bitboxClient.btcAddress(
    bitboxApiNetwork(bitboxManager),
    [...account.keypathAccount, change, index],
    bitboxScriptConfigFromMultisigAccount(account),
    true
  );
}

async function displayPolicyAddress({
  policy,
  bitboxManager,
  change,
  index
}: {
  policy: BitBoxPolicy;
  bitboxManager: BitBoxManager;
  change: number;
  index: number;
}) {
  return bitboxManager.bitboxClient.btcAddress(
    bitboxApiNetwork(bitboxManager),
    bitboxAddressKeypathFromPolicy({ policy, bitboxManager, change, index }),
    bitboxScriptConfigFromPolicy({ policy, bitboxManager }),
    true
  );
}

export async function displayBitBoxAddress({
  descriptor,
  bitboxManager,
  change = 0,
  index
}: BitBoxAddressDisplayParams): Promise<string | void> {
  const output = outputForDisplay({ descriptor, bitboxManager, change, index });
  const standardPolicy = await bitboxPolicyFromStandard({
    output,
    bitboxManager
  });
  if (standardPolicy)
    return displayStandardAddress({
      policy: standardPolicy,
      bitboxManager,
      change,
      index
    });

  const policy = await bitboxPolicyFromState({ output, bitboxManager });
  if (!policy)
    throw new Error(
      `BitBox policy not registered; call registerBitBoxWallet first`
    );
  return policy.account
    ? displayMultisigAddress({ policy, bitboxManager, change, index })
    : displayPolicyAddress({ policy, bitboxManager, change, index });
}

export async function displayAddress({
  descriptor,
  manager,
  change,
  index
}: Omit<BitBoxAddressDisplayParams, 'bitboxManager'> & {
  manager: BitBoxManager;
}): Promise<string | void> {
  return displayBitBoxAddress({
    descriptor,
    bitboxManager: manager,
    ...(change !== undefined ? { change } : {}),
    index
  });
}

export type BitBoxManagerParams = {
  bitboxManager: BitBoxManager;
};

export type BitBoxManagerShape = {
  Output: OutputConstructor;
  network: Network;
};
