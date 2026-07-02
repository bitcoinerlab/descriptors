// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { compare, toHex } from 'uint8array-tools';
import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import type { OutputInstance } from '../descriptors';
import {
  policyFromOutput,
  policyFromPsbtInput,
  policyFromStandard
} from '../hww/policies';
import type { HardwareWalletPolicyManager, WalletPolicy } from '../hww/types';
import { coinTypeFromNetwork } from '../networkUtils';
import type {
  BitBoxKeyOriginInfo,
  BitBoxManager,
  BitBoxMultisigAccount,
  BitBoxPolicy,
  BitBoxScriptConfig
} from './types';
import {
  bitboxCoin,
  bitboxRegisterXpubType,
  bitboxSimpleType,
  getBitBoxMasterFingerprint,
  getBitBoxXpub
} from './client';
import { bitboxKeypathFromString } from './utils';

export function hwwManagerFromBitBoxManager(
  bitboxManager: BitBoxManager
): HardwareWalletPolicyManager {
  const policies = bitboxManager.bitboxState.policies?.map(bitboxPolicy => ({
    ...(bitboxPolicy.policyName !== undefined
      ? { policyName: bitboxPolicy.policyName }
      : {}),
    descriptorTemplate: bitboxPolicy.descriptorTemplate,
    keyRoots: bitboxPolicy.keyRoots
  }));
  return {
    Output: bitboxManager.Output,
    network: bitboxManager.network,
    ...(policies !== undefined ? { policies } : {}),
    getMasterFingerprint: () => getBitBoxMasterFingerprint({ bitboxManager }),
    getXpub: originPath => getBitBoxXpub({ originPath, bitboxManager })
  };
}

export function bitboxScriptConfigFromMultisigAccount(
  account: BitBoxMultisigAccount
): BitBoxScriptConfig {
  return {
    multisig: {
      threshold: account.threshold,
      xpubs: account.xpubs,
      ourXpubIndex: account.ourXpubIndex,
      scriptType: account.scriptType
    }
  };
}

function bitboxKeyOriginInfoFromKeyRoot(keyRoot: string): BitBoxKeyOriginInfo {
  const parsed = parseKeyRoot(keyRoot);
  return {
    ...(parsed.masterFingerprint
      ? { rootFingerprint: toHex(parsed.masterFingerprint) }
      : {}),
    ...(parsed.originPath
      ? { keypath: bitboxKeypathFromString(parsed.originPath) }
      : {}),
    xpub: parsed.xpub
  };
}

export function bitboxOwnOriginPathFromPolicy({
  policy,
  bitboxManager
}: {
  policy: BitBoxPolicy | WalletPolicy;
  bitboxManager: BitBoxManager;
}): string {
  const masterFingerprint = bitboxManager.bitboxState.masterFingerprint;
  if (!masterFingerprint)
    throw new Error(`BitBox master fingerprint required for policy`);

  const parsedKeyRoots = policy.keyRoots.map(parseKeyRoot);
  const ownKeyRoot = parsedKeyRoots.find(
    keyRoot =>
      keyRoot.masterFingerprint &&
      compare(keyRoot.masterFingerprint, masterFingerprint) === 0
  );
  if (!ownKeyRoot)
    throw new Error(`BitBox policy does not contain this device`);
  if (!ownKeyRoot.originPath)
    throw new Error(`BitBox policy key must include origin information`);
  return ownKeyRoot.originPath;
}

export function bitboxSigningKeypathFromPolicy({
  policy,
  bitboxManager
}: {
  policy: BitBoxPolicy | WalletPolicy;
  bitboxManager: BitBoxManager;
}): number[] {
  return bitboxKeypathFromString(
    bitboxOwnOriginPathFromPolicy({ policy, bitboxManager })
  );
}

export function bitboxAddressKeypathFromPolicy({
  policy,
  bitboxManager,
  change,
  index
}: {
  policy: BitBoxPolicy | WalletPolicy;
  bitboxManager: BitBoxManager;
  change: number;
  index: number;
}): number[] {
  return bitboxKeypathFromString(
    `${bitboxOwnOriginPathFromPolicy({ policy, bitboxManager })}/${change}/${index}`
  );
}

export function bitboxScriptConfigFromPolicy({
  policy,
  bitboxManager
}: {
  policy: BitBoxPolicy | WalletPolicy;
  bitboxManager: BitBoxManager;
}): BitBoxScriptConfig {
  if (policy.descriptorTemplate.match(/^wsh\((?:sortedmulti|multi)\(/)) {
    const account =
      'account' in policy && policy.account
        ? policy.account
        : bitboxAccountFromPolicy({ policy, bitboxManager });
    return bitboxScriptConfigFromMultisigAccount(account);
  }

  if (policy.descriptorTemplate.match(/^sh\(wpkh\(@0\/\*\*\)\)$/)) {
    return {
      simpleType: bitboxSimpleType({
        descriptorTemplate: policy.descriptorTemplate,
        bitboxManager
      })
    };
  }

  if (policy.descriptorTemplate.match(/^(wpkh|tr)\(@0\/\*\*\)$/)) {
    return {
      simpleType: bitboxSimpleType({
        descriptorTemplate: policy.descriptorTemplate,
        bitboxManager
      })
    };
  }

  return {
    policy: {
      policy: policy.descriptorTemplate,
      keys: policy.keyRoots.map(bitboxKeyOriginInfoFromKeyRoot)
    }
  };
}

function walletPolicyToBitBoxPolicy(policy: WalletPolicy): BitBoxPolicy {
  return {
    ...(policy.policyName !== undefined
      ? { policyName: policy.policyName }
      : {}),
    descriptorTemplate: policy.descriptorTemplate,
    keyRoots: policy.keyRoots
  };
}

function parseKeyRoot(keyRoot: string): {
  masterFingerprint?: Uint8Array;
  originPath?: string;
  xpub: string;
} {
  const originMatch = keyRoot.match(/^\[([0-9a-fA-F]{8})([^\]]*)\](.+)$/);
  if (!originMatch) return { xpub: keyRoot };
  return {
    masterFingerprint: Uint8Array.from(
      originMatch[1]!.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
    ),
    ...(originMatch[2] ? { originPath: originMatch[2] } : {}),
    xpub: originMatch[3]!
  };
}

export function bitboxAccountFromPolicy({
  policy,
  bitboxManager
}: {
  policy: BitBoxPolicy | WalletPolicy;
  bitboxManager: BitBoxManager;
}): BitBoxMultisigAccount {
  const match = policy.descriptorTemplate.match(
    /^wsh\((?:sortedmulti|multi)\((\d+),(.+)\)\)$/
  );
  if (!match)
    throw new Error(
      `BitBox02 JS API supports registration only for wsh(sortedmulti(...)) or wsh(multi(...)) policies`
    );

  const threshold = Number(match[1]);
  const keyTokens = match[2]!.split(',').map(token => token.trim());
  if (!Number.isInteger(threshold) || threshold < 1)
    throw new Error(`Invalid BitBox02 multisig threshold`);
  if (keyTokens.length !== policy.keyRoots.length)
    throw new Error(`BitBox02 policy key count mismatch`);
  for (let i = 0; i < keyTokens.length; i++) {
    if (keyTokens[i] !== `@${i}/**`)
      throw new Error(`BitBox02 multisig key ${i} must be @${i}/**`);
  }

  const parsedKeyRoots = policy.keyRoots.map(parseKeyRoot);
  const masterFingerprint = bitboxManager.bitboxState.masterFingerprint;
  if (!masterFingerprint)
    throw new Error(`BitBox02 master fingerprint required for multisig policy`);
  const ourXpubIndex = parsedKeyRoots.findIndex(
    keyRoot =>
      keyRoot.masterFingerprint &&
      compare(keyRoot.masterFingerprint, masterFingerprint) === 0
  );
  if (ourXpubIndex === -1)
    throw new Error(`BitBox02 multisig policy does not contain this device`);

  const ourOriginPath = parsedKeyRoots[ourXpubIndex]!.originPath;
  if (!ourOriginPath)
    throw new Error(`BitBox02 multisig key must include origin information`);

  const expectedCoinType = coinTypeFromNetwork(bitboxManager.network);
  const originMatch = ourOriginPath.match(/^\/48'\/([01])'\/(\d+)'\/2'$/);
  if (!originMatch || Number(originMatch[1]) !== expectedCoinType) {
    throw new Error(
      `BitBox02 JS API supports multisig only at m/48'/${expectedCoinType}'/<account>'/2'`
    );
  }

  return {
    keypathAccount: bitboxKeypathFromString(ourOriginPath),
    threshold,
    xpubs: parsedKeyRoots.map(keyRoot => keyRoot.xpub),
    ourXpubIndex,
    scriptType: 'p2wsh'
  };
}

export async function bitboxPolicyFromPsbtInput({
  psbt,
  index,
  bitboxManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  bitboxManager: BitBoxManager;
}): Promise<BitBoxPolicy | null> {
  const policy = await policyFromPsbtInput({
    psbt,
    index,
    hwwManager: hwwManagerFromBitBoxManager(bitboxManager)
  });
  return policy ? walletPolicyToBitBoxPolicy(policy) : null;
}

export async function bitboxPolicyFromOutput({
  output,
  bitboxManager
}: {
  output: OutputInstance;
  bitboxManager: BitBoxManager;
}): Promise<{ descriptorTemplate: string; keyRoots: string[] } | null> {
  return policyFromOutput({
    output,
    hwwManager: hwwManagerFromBitBoxManager(bitboxManager)
  });
}

export async function bitboxPolicyFromStandard({
  output,
  bitboxManager
}: {
  output: OutputInstance;
  bitboxManager: BitBoxManager;
}): Promise<BitBoxPolicy | null> {
  const policy = await policyFromStandard({
    output,
    hwwManager: hwwManagerFromBitBoxManager(bitboxManager)
  });
  return policy ? walletPolicyToBitBoxPolicy(policy) : null;
}

export async function bitboxPolicyFromState({
  output,
  bitboxManager
}: {
  output: OutputInstance;
  bitboxManager: BitBoxManager;
}): Promise<BitBoxPolicy | null> {
  const result = await bitboxPolicyFromOutput({ output, bitboxManager });
  if (!result) throw new Error(`Error: output does not have a BitBox02 input`);
  const { descriptorTemplate, keyRoots } = result;
  const policies = (bitboxManager.bitboxState.policies || []).filter(policy => {
    if (policy.descriptorTemplate !== descriptorTemplate) return false;
    if (policy.keyRoots.length !== keyRoots.length) return false;
    return policy.keyRoots.every(
      (keyRoot, index) => keyRoot === keyRoots[index]
    );
  });
  if (policies.length > 1) throw new Error(`Error: duplicated BitBox02 policy`);
  return policies[0] ?? null;
}

export async function registerBitBoxWallet({
  descriptor,
  bitboxManager,
  policyName
}: {
  descriptor: string;
  bitboxManager: BitBoxManager;
  policyName: string;
}): Promise<void> {
  const { bitboxClient, bitboxState, network, Output } = bitboxManager;

  const output = new Output({
    descriptor,
    ...(descriptor.includes('*') ? { index: 0 } : {}),
    ...(descriptor.includes('/<') ? { change: 0 } : {}),
    network
  });

  if (await bitboxPolicyFromStandard({ output, bitboxManager })) return;
  const result = await bitboxPolicyFromOutput({ output, bitboxManager });
  if (!result) throw new Error(`Error: output does not have a BitBox02 input`);
  if (!bitboxState.policies) bitboxState.policies = [];

  const existingPolicy = await bitboxPolicyFromState({
    output,
    bitboxManager
  });
  if (existingPolicy) {
    if (existingPolicy.policyName !== policyName)
      throw new Error(
        `Error: policy was already registered with a different name: ${existingPolicy.policyName}`
      );
    return;
  }

  const policy: BitBoxPolicy = {
    policyName,
    descriptorTemplate: result.descriptorTemplate,
    keyRoots: result.keyRoots
  };
  const account = policy.descriptorTemplate.match(
    /^wsh\((?:sortedmulti|multi)\(/
  )
    ? bitboxAccountFromPolicy({ policy, bitboxManager })
    : undefined;
  const scriptConfig = account
    ? bitboxScriptConfigFromMultisigAccount(account)
    : bitboxScriptConfigFromPolicy({ policy, bitboxManager });
  const registered = await bitboxClient.btcIsScriptConfigRegistered(
    bitboxCoin(bitboxManager),
    scriptConfig,
    account?.keypathAccount
  );
  if (!registered)
    await bitboxClient.btcRegisterScriptConfig(
      bitboxCoin(bitboxManager),
      scriptConfig,
      account?.keypathAccount,
      bitboxRegisterXpubType(bitboxManager),
      policyName
    );
  bitboxState.policies.push({ ...policy, ...(account ? { account } : {}) });
}

export function fingerprintHex(
  bitboxManager: BitBoxManager
): string | undefined {
  return bitboxManager.bitboxState.masterFingerprint
    ? toHex(bitboxManager.bitboxState.masterFingerprint)
    : undefined;
}
