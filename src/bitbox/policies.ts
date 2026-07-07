// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { compare, fromHex, toHex } from 'uint8array-tools';
import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import type { OutputInstance } from '../descriptors';
import {
  policyFromOutput as hwwPolicyFromOutput,
  policyFromPsbtInput as hwwPolicyFromPsbtInput,
  policyFromStandard as hwwPolicyFromStandard
} from '../hww/policies';
import type { HWWPolicy, HWWPolicyResolver } from '../hww/types';
import type {
  BitBoxKeyOriginInfo,
  BitBoxMultisigScriptType,
  BitBoxPolicy,
  BitBoxScriptConfig,
  BitBoxSession
} from './types';
import { coinTypeFromNetwork } from '../networkUtils';
import {
  apiNetwork,
  simpleType,
  getMasterFingerprint,
  getXpub
} from './client';

function policyResolverFromSession(session: BitBoxSession): HWWPolicyResolver {
  const knownPolicies = session.store.policies?.map(policy => ({
    ...(policy.name !== undefined ? { name: policy.name } : {}),
    descriptorTemplate: policy.descriptorTemplate,
    keyRoots: policy.keyRoots
  }));
  return {
    Output: session.Output,
    network: session.network,
    ...(knownPolicies !== undefined ? { knownPolicies } : {}),
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    getAccountXpub: originPath => getXpub({ originPath, session })
  };
}

function keyOriginInfoFromKeyRoot(keyRoot: string): BitBoxKeyOriginInfo {
  const parsed = parseKeyRoot(keyRoot);
  return {
    ...(parsed.masterFingerprint
      ? { rootFingerprint: toHex(parsed.masterFingerprint) }
      : {}),
    ...(parsed.originPath ? { keypath: `m${parsed.originPath}` } : {}),
    xpub: parsed.xpub
  };
}

type NativeMultisigPolicyDetails = {
  accountKeypath: string;
  threshold: number;
  xpubs: string[];
  ourXpubIndex: number;
  scriptType: BitBoxMultisigScriptType;
};

/** Turns native multisig details into the BitBox API script config. */
function scriptConfigFromNativeMultisigDetails(
  details: NativeMultisigPolicyDetails
): BitBoxScriptConfig {
  return {
    multisig: {
      threshold: details.threshold,
      xpubs: details.xpubs,
      ourXpubIndex: details.ourXpubIndex,
      scriptType: details.scriptType
    }
  };
}

/** Extracts native BitBox multisig details from a stored policy. */
function nativeMultisigDetailsFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy | HWWPolicy;
  session: BitBoxSession;
}): NativeMultisigPolicyDetails {
  const match = policy.descriptorTemplate.match(
    /^wsh\((?:sortedmulti|multi)\((\d+),(.+)\)\)$/
  );
  if (!match)
    throw new Error(
      `BitBox02 native multisig supports only wsh(sortedmulti(...)) or wsh(multi(...)) policies`
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

  const masterFingerprint = session.store.masterFingerprint;
  if (!masterFingerprint)
    throw new Error(`BitBox02 master fingerprint required for multisig policy`);
  const parsedKeyRoots = policy.keyRoots.map(parseKeyRoot);
  const ourXpubIndex = parsedKeyRoots.findIndex(
    keyRoot =>
      keyRoot.masterFingerprint &&
      compare(keyRoot.masterFingerprint, fromHex(masterFingerprint)) === 0
  );
  if (ourXpubIndex === -1)
    throw new Error(`BitBox02 multisig policy does not contain this device`);

  const ourOriginPath = parsedKeyRoots[ourXpubIndex]!.originPath;
  if (!ourOriginPath)
    throw new Error(`BitBox02 multisig key must include origin information`);

  const expectedCoinType = coinTypeFromNetwork(session.network);
  const originMatch = ourOriginPath.match(/^\/48'\/([01])'\/(\d+)'\/2'$/);
  if (!originMatch || Number(originMatch[1]) !== expectedCoinType) {
    throw new Error(
      `BitBox02 native multisig supports only m/48'/${expectedCoinType}'/<account>'/2'`
    );
  }

  return {
    accountKeypath: `m${ourOriginPath}`,
    threshold,
    xpubs: parsedKeyRoots.map(keyRoot => keyRoot.xpub),
    ourXpubIndex,
    scriptType: 'p2wsh'
  };
}

function ownOriginPathFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy | HWWPolicy;
  session: BitBoxSession;
}): string {
  const masterFingerprint = session.store.masterFingerprint;
  if (!masterFingerprint)
    throw new Error(`BitBox master fingerprint required for policy`);

  const parsedKeyRoots = policy.keyRoots.map(parseKeyRoot);
  const ownKeyRoot = parsedKeyRoots.find(
    keyRoot =>
      keyRoot.masterFingerprint &&
      compare(keyRoot.masterFingerprint, fromHex(masterFingerprint)) === 0
  );
  if (!ownKeyRoot)
    throw new Error(`BitBox policy does not contain this device`);
  if (!ownKeyRoot.originPath)
    throw new Error(`BitBox policy key must include origin information`);
  return ownKeyRoot.originPath;
}

export function signingKeypathFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy | HWWPolicy;
  session: BitBoxSession;
}): string {
  return `m${ownOriginPathFromPolicy({ policy, session })}`;
}

export function addressKeypathFromPolicy({
  policy,
  session,
  change,
  index
}: {
  policy: BitBoxPolicy | HWWPolicy;
  session: BitBoxSession;
  change: number;
  index: number;
}): string {
  return `m${ownOriginPathFromPolicy({ policy, session })}/${change}/${index}`;
}

export function scriptConfigFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy | HWWPolicy;
  session: BitBoxSession;
}): BitBoxScriptConfig {
  if (policy.descriptorTemplate.match(/^wsh\((?:sortedmulti|multi)\(/)) {
    return scriptConfigFromNativeMultisigDetails(
      nativeMultisigDetailsFromPolicy({ policy, session })
    );
  }

  if (policy.descriptorTemplate.match(/^sh\(wpkh\(@0\/\*\*\)\)$/)) {
    return {
      simpleType: simpleType({
        descriptorTemplate: policy.descriptorTemplate,
        session
      })
    };
  }

  if (policy.descriptorTemplate.match(/^pkh\(@0\/\*\*\)$/)) {
    throw new Error(
      `BitBox02 does not support top-level legacy p2pkh descriptors; use shWpkh, wpkh, or tr`
    );
  }

  if (policy.descriptorTemplate.match(/^(wpkh|tr)\(@0\/\*\*\)$/)) {
    return {
      simpleType: simpleType({
        descriptorTemplate: policy.descriptorTemplate,
        session
      })
    };
  }

  return {
    policy: {
      policy: policy.descriptorTemplate,
      keys: policy.keyRoots.map(keyOriginInfoFromKeyRoot)
    }
  };
}

const unsupportedHashFragment = /\b(?:sha256|hash256|hash160|ripemd160)\(/;

export function assertPolicyCanDerive(policy: BitBoxPolicy): void {
  if (!unsupportedHashFragment.test(policy.descriptorTemplate)) return;
  throw new Error(
    `BitBox generic policy derivation with Miniscript hash fragments is disabled because BitBox02 firmware marks sha256/hash256/hash160/ripemd160 policy fragments unsupported and firmware 9.26.1 has been observed to crash while deriving sha256(...). Avoid hashlocks with BitBox or use another signer until BitBox firmware/API support is confirmed.`
  );
}

function isDuplicateError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'bitbox-duplicate'
  );
}

function hwwPolicyToPolicy(policy: HWWPolicy): BitBoxPolicy {
  return {
    ...(policy.name !== undefined ? { name: policy.name } : {}),
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
    masterFingerprint: fromHex(originMatch[1]!),
    ...(originMatch[2] ? { originPath: originMatch[2] } : {}),
    xpub: originMatch[3]!
  };
}

export async function policyFromPsbtInput({
  psbt,
  index,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  session: BitBoxSession;
}): Promise<BitBoxPolicy | null> {
  const policy = await hwwPolicyFromPsbtInput({
    psbt,
    index,
    policyResolver: policyResolverFromSession(session)
  });
  return policy ? hwwPolicyToPolicy(policy) : null;
}

async function policyFromOutput({
  output,
  session
}: {
  output: OutputInstance;
  session: BitBoxSession;
}): Promise<{ descriptorTemplate: string; keyRoots: string[] } | null> {
  return hwwPolicyFromOutput({
    output,
    policyResolver: policyResolverFromSession(session)
  });
}

export async function policyFromStandard({
  output,
  session
}: {
  output: OutputInstance;
  session: BitBoxSession;
}): Promise<BitBoxPolicy | null> {
  const policy = await hwwPolicyFromStandard({
    output,
    policyResolver: policyResolverFromSession(session)
  });
  return policy ? hwwPolicyToPolicy(policy) : null;
}

export async function policyFromStore({
  output,
  session
}: {
  output: OutputInstance;
  session: BitBoxSession;
}): Promise<BitBoxPolicy | null> {
  const result = await policyFromOutput({ output, session });
  if (!result) throw new Error(`Error: output does not have a BitBox02 input`);
  const { descriptorTemplate, keyRoots } = result;
  const policies = (session.store.policies || []).filter(policy => {
    if (policy.descriptorTemplate !== descriptorTemplate) return false;
    if (policy.keyRoots.length !== keyRoots.length) return false;
    return policy.keyRoots.every(
      (keyRoot, index) => keyRoot === keyRoots[index]
    );
  });
  if (policies.length > 1) throw new Error(`Error: duplicated BitBox02 policy`);
  return policies[0] ?? null;
}

export async function registerWalletPolicy({
  descriptor,
  session,
  name
}: {
  descriptor: string;
  session: BitBoxSession;
  /** Name shown by the device for this policy. */
  name: string;
}): Promise<BitBoxSession['store']> {
  const { client, store, network, Output } = session;

  const output = new Output({
    descriptor,
    ...(descriptor.includes('*') ? { index: 0 } : {}),
    ...(descriptor.includes('/<') ? { change: 0 } : {}),
    network
  });

  const standardPolicy = await policyFromStandard({
    output,
    session
  });
  if (standardPolicy) {
    simpleType({
      descriptorTemplate: standardPolicy.descriptorTemplate,
      session
    });
    return store;
  }
  const result = await policyFromOutput({ output, session });
  if (!result) throw new Error(`Error: output does not have a BitBox02 input`);
  if (!store.policies) store.policies = [];

  const existingPolicy = await policyFromStore({
    output,
    session
  });
  if (existingPolicy) {
    if (existingPolicy.name !== name)
      throw new Error(
        `Error: policy was already registered with a different name: ${existingPolicy.name}`
      );
    return store;
  }

  const policy: BitBoxPolicy = {
    name,
    descriptorTemplate: result.descriptorTemplate,
    keyRoots: result.keyRoots
  };
  const nativeMultisigDetails = policy.descriptorTemplate.match(
    /^wsh\((?:sortedmulti|multi)\(/
  )
    ? nativeMultisigDetailsFromPolicy({ policy, session })
    : undefined;
  const scriptConfig = nativeMultisigDetails
    ? scriptConfigFromNativeMultisigDetails(nativeMultisigDetails)
    : scriptConfigFromPolicy({ policy, session });
  const accountKeypath = nativeMultisigDetails?.accountKeypath;
  const registered = await client.btcIsScriptConfigRegistered(
    apiNetwork(session),
    scriptConfig,
    accountKeypath
  );
  if (!registered) {
    try {
      await client.btcRegisterScriptConfig(
        apiNetwork(session),
        scriptConfig,
        accountKeypath,
        'autoXpubTpub',
        name
      );
    } catch (error) {
      if (!isDuplicateError(error)) throw error;
      const registeredAfterDuplicate = await client.btcIsScriptConfigRegistered(
        apiNetwork(session),
        scriptConfig,
        accountKeypath
      );
      if (!registeredAfterDuplicate) throw error;
    }
  }
  store.policies.push(policy);
  return store;
}
