// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { compare, fromHex, toHex } from 'uint8array-tools';
import { parseKeyRoot } from '../hww/helpers';
import { parseP2wshSortedmultiPolicy } from '../hww/policies';
import type {
  BitBoxKeyOriginInfo,
  BitBoxMultisigScriptType,
  BitBoxPolicy,
  BitBoxScriptConfig,
  BitBoxSession
} from './types';
import { coinTypeFromNetwork } from '../networkUtils';
import { simpleType } from './client';

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
  policy: BitBoxPolicy;
  session: BitBoxSession;
}): NativeMultisigPolicyDetails | null {
  const sortedmultiPolicy = parseP2wshSortedmultiPolicy(policy);
  if (!sortedmultiPolicy) return null;

  if (sortedmultiPolicy.keyIndexes.length !== policy.keyRoots.length)
    throw new Error(`BitBox02 policy key count mismatch`);
  for (let i = 0; i < sortedmultiPolicy.keyIndexes.length; i++) {
    if (sortedmultiPolicy.keyIndexes[i] !== i)
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
    threshold: sortedmultiPolicy.threshold,
    xpubs: parsedKeyRoots.map(keyRoot => keyRoot.xpub),
    ourXpubIndex,
    scriptType: 'p2wsh'
  };
}

function ownOriginPathFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy;
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

/** Returns the account keypath BitBox uses to sign this policy. */
export function signingKeypathFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
}): string {
  return `m${ownOriginPathFromPolicy({ policy, session })}`;
}

/** Returns the full BitBox keypath for one address in this policy. */
export function addressKeypathFromPolicy({
  policy,
  session,
  change,
  index
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
  change: number;
  index: number;
}): string {
  return `m${ownOriginPathFromPolicy({ policy, session })}/${change}/${index}`;
}

/** Converts a descriptor policy into the BitBox script config to send. */
export function scriptConfigFromPolicy({
  policy,
  session
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
}): BitBoxScriptConfig {
  // Try to see if this policy is a sortedmulti descriptor, since BitBox does
  // not accept wsh(sortedmulti(...)) as a generic policy and instead requires
  // the native multisig format built by scriptConfigFromNativeMultisigDetails.
  const nativeMultisigDetails = nativeMultisigDetailsFromPolicy({
    policy,
    session
  });
  if (nativeMultisigDetails)
    return scriptConfigFromNativeMultisigDetails(nativeMultisigDetails);

  // Now detect standard scripts since BitBox also requires special treatment.
  if (
    // pkh is included even though BitBox does not support it. simpleType throws.
    ['pkh(@0/**)', 'sh(wpkh(@0/**))', 'wpkh(@0/**)', 'tr(@0/**)'].includes(
      policy.descriptorTemplate
    )
  ) {
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

/**
 * Builds the BitBox script config and account path used for registration.
 *
 * Native multisig registration needs `accountKeypath`. Generic policy
 * registration leaves it undefined.
 */
export function scriptConfigForRegistration({
  policy,
  session
}: {
  policy: BitBoxPolicy;
  session: BitBoxSession;
}): { scriptConfig: BitBoxScriptConfig; accountKeypath?: string } {
  const nativeMultisigDetails = nativeMultisigDetailsFromPolicy({
    policy,
    session
  });
  return nativeMultisigDetails
    ? {
        scriptConfig: scriptConfigFromNativeMultisigDetails(
          nativeMultisigDetails
        ),
        accountKeypath: nativeMultisigDetails.accountKeypath
      }
    : { scriptConfig: scriptConfigFromPolicy({ policy, session }) };
}

const unsupportedHashFragment = /\b(?:sha256|hash256|hash160|ripemd160)\(/;

/** Throws when BitBox should not derive addresses for this policy. */
export function assertPolicyCanDerive(policy: BitBoxPolicy): void {
  if (!unsupportedHashFragment.test(policy.descriptorTemplate)) return;
  throw new Error(
    `BitBox generic policy derivation with Miniscript hash fragments is disabled because BitBox02 firmware marks sha256/hash256/hash160/ripemd160 policy fragments unsupported and firmware 9.26.1 has been observed to crash while deriving sha256(...). Avoid hashlocks with BitBox or use another signer until BitBox firmware/API support is confirmed.`
  );
}
