// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// OutputConstructor is needed only for the deprecated LedgerManager override.
// Remove this type import and the optional Output parameter in v4.
import {
  getOutputConstructorOrThrow,
  type OutputConstructor,
  type OutputInstance
} from '../descriptors';
import {
  PsbtLike,
  ScureTransactionLike,
  getBitcoinLibOrThrow,
  toBIP32Interface
} from '../bitcoinLib';
import { toPsbt } from '../psbt';
import { compare, toHex } from 'uint8array-tools';
import type { Network } from '../networks';
import { coinTypeFromNetwork } from '../networkUtils';
import { reOriginPath } from '../re';
import type { ExpansionMap, KeyInfo } from '../types';
import type { TapTreeInfoNode } from '../tapTree';

/**
 * Descriptor policy used by shared hardware-wallet helpers.
 *
 * `descriptorTemplate` is the device policy template, for example
 * `wsh(sortedmulti(2,@0/**,@1/**))`.
 *
 * `keyRoots` contains the xpub roots that replace `@0`, `@1`, and so on.
 * `name` is optional because standard policies and freshly derived policies do
 * not have a device registration name.
 */
export type HWWPolicy = {
  /** Human-readable policy name shown by the device when supported. */
  name?: string;
  /** Descriptor template with `@0`, `@1`, ... placeholders. */
  descriptorTemplate: string;
  /** Xpub roots used by the descriptor template placeholders. */
  keyRoots: string[];
};

export type DerivedHWWPolicy = HWWPolicy & {
  change: number;
  index: number;
};

function standardTemplateForOriginPath({
  originPath,
  network
}: {
  originPath: string;
  network: Network;
}): string | undefined {
  const coinType = coinTypeFromNetwork(network);
  if (originPath.match(new RegExp(`^/44'/${coinType}'/(\\d+)'$`)))
    return 'pkh(@0/**)';
  if (originPath.match(new RegExp(`^/49'/${coinType}'/(\\d+)'$`)))
    return 'sh(wpkh(@0/**))';
  if (originPath.match(new RegExp(`^/84'/${coinType}'/(\\d+)'$`)))
    return 'wpkh(@0/**)';
  if (originPath.match(new RegExp(`^/86'/${coinType}'/(\\d+)'$`)))
    return 'tr(@0/**)';
  return undefined;
}

export function isStandardPolicy({
  descriptorTemplate,
  keyRoots,
  network
}: {
  descriptorTemplate: string;
  keyRoots: string[];
  network: Network;
}): boolean {
  if (keyRoots.length !== 1) return false;
  const originPath = keyRoots[0]?.match(reOriginPath)?.[1];
  if (!originPath) return false;
  return (
    descriptorTemplate ===
    standardTemplateForOriginPath({ originPath, network })
  );
}

/** Finds the hardware-wallet policy that matches a PSBT input. */
export async function policyForPsbtInput({
  getMasterFingerprint,
  getAccountXpub,
  knownPolicies,
  network,
  psbt,
  index,
  legacyOutput
}: {
  /** Reads the connected device master fingerprint. */
  getMasterFingerprint(): Promise<Uint8Array>;
  /** Reads an account xpub when a standard policy must be reconstructed. */
  getAccountXpub(originPath: string): Promise<string>;
  /** Policies already known by the app or registered with the device. */
  knownPolicies?: HWWPolicy[];
  /** Bitcoin network used to identify standard paths and rebuild scripts. */
  network: Network;
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  /**
   * @deprecated 3.x LedgerManager compatibility only. Remove in v4 and always
   * use the active package backend.
   */
  legacyOutput?: OutputConstructor;
}): Promise<HWWPolicy | undefined> {
  const bitcoinLib = getBitcoinLibOrThrow();
  psbt = toPsbt(psbt);
  // In v4, remove legacyOutput and keep getOutputConstructorOrThrow().
  const Output = legacyOutput ?? getOutputConstructorOrThrow();
  const { Transaction } = bitcoinLib;
  const input = psbt.data.inputs[index];
  if (!input) throw new Error(`Error: input ${index} not available`);

  const keyDerivations = [
    ...(input.bip32Derivation || []),
    ...(input.tapBip32Derivation || [])
  ];
  if (keyDerivations.length === 0) return;

  const masterFingerprint = await getMasterFingerprint();
  if (
    !keyDerivations.some(
      keyDerivation =>
        compare(keyDerivation.masterFingerprint, masterFingerprint) === 0
    )
  )
    return;

  let scriptPubKey: Uint8Array | undefined;
  if (input.nonWitnessUtxo) {
    const txInput = psbt.txInputs[index];
    if (!txInput) throw new Error(`Error: tx input ${index} not available`);
    const vout = txInput.index;
    const nonWitnessScript = Transaction.fromBuffer(input.nonWitnessUtxo).outs[
      vout
    ]?.script;
    scriptPubKey = nonWitnessScript;
  } else if (input.witnessUtxo) {
    scriptPubKey = input.witnessUtxo.script;
  }
  if (!scriptPubKey)
    throw new Error(`Could not retrieve scriptPubKey for input ${index}.`);

  for (const keyDerivation of keyDerivations) {
    if (compare(keyDerivation.masterFingerprint, masterFingerprint) === 0) {
      const match = keyDerivation.path.match(/m((\/\d+['hH])*)(\/\d+\/\d+)?/);
      const originPath = match ? match[1] : undefined;
      const keyPath = match ? match[3] : undefined;

      if (originPath && keyPath) {
        const [, strChange, strIndex] = keyPath.split('/');
        if (!strChange || !strIndex)
          throw new Error(`keyPath ${keyPath} incorrectly extracted`);
        const change = parseInt(strChange, 10);
        const index = parseInt(strIndex, 10);

        let standardPolicy;
        if (change === 0 || change === 1) {
          const standardTemplate = standardTemplateForOriginPath({
            originPath,
            network
          });
          if (standardTemplate) {
            const xpub = await getAccountXpub(originPath);
            standardPolicy = {
              descriptorTemplate: standardTemplate,
              keyRoots: [`[${toHex(masterFingerprint)}${originPath}]${xpub}`]
            };
          }
        }

        const policies = [...(knownPolicies || [])];
        if (standardPolicy) policies.push(standardPolicy);

        for (const policy of policies) {
          let descriptor: string | undefined = policy.descriptorTemplate;
          descriptor = descriptor.replace(/\/\*\*/g, `/<0;1>/*`);
          let tupleMismatch = false;
          descriptor = descriptor.replace(
            /\/<(\d+);(\d+)>/g,
            (token, strM: string, strN: string) => {
              const [M, N] = [parseInt(strM, 10), parseInt(strN, 10)];
              if (M === change || N === change) return `/${change}`;
              tupleMismatch = true;
              return token;
            }
          );
          if (tupleMismatch) descriptor = undefined;
          if (descriptor) {
            descriptor = descriptor.replace(/\/\*/g, `/${index}`);
            for (let i = policy.keyRoots.length - 1; i >= 0; i--) {
              const keyRoot = policy.keyRoots[i];
              if (!keyRoot)
                throw new Error(`keyRoot ${keyRoot} invalidly extracted.`);
              descriptor = descriptor.replace(
                new RegExp(`@${i}`, 'g'),
                keyRoot
              );
            }

            if (descriptor) {
              const policyScriptPubKey = new Output({
                descriptor,
                network
              }).getScriptPubKey();

              if (compare(policyScriptPubKey, scriptPubKey) === 0) {
                return policy;
              }
            }
          }
        }
      }
    }
  }
  return;
}

/** Builds the descriptor policy for an output that contains this device. */
export async function derivePolicyFromOutput({
  output,
  getMasterFingerprint
}: {
  output: OutputInstance;
  /** Reads the connected device master fingerprint. */
  getMasterFingerprint(): Promise<Uint8Array>;
}): Promise<DerivedHWWPolicy | null> {
  const expanded = output.expand();
  let expandedExpression = expanded.expandedExpression;
  const expansionMap = expanded.expansionMap
    ? ({ ...expanded.expansionMap } as ExpansionMap)
    : undefined;

  if (
    expandedExpression?.startsWith('tr(@0,') &&
    expansionMap &&
    expanded.tapTreeInfo
  ) {
    const keyExpressionToGlobalPlaceholder = new Map<string, string>(
      Object.entries(expansionMap).map(([placeholder, keyInfo]) => [
        keyInfo.keyExpression,
        placeholder
      ])
    );
    let nextPlaceholderIndex = Object.keys(expansionMap).length;

    const globalPlaceholderFor = (keyInfo: KeyInfo): string => {
      const existing = keyExpressionToGlobalPlaceholder.get(
        keyInfo.keyExpression
      );
      if (existing) return existing;
      const placeholder = `@${nextPlaceholderIndex}`;
      nextPlaceholderIndex += 1;
      keyExpressionToGlobalPlaceholder.set(keyInfo.keyExpression, placeholder);
      expansionMap[placeholder] = keyInfo;
      return placeholder;
    };

    const remapTapTree = (node: TapTreeInfoNode): string => {
      if ('expression' in node) {
        let remappedMiniscript =
          node.expandedExpression ?? node.expandedMiniscript;
        if (!remappedMiniscript)
          throw new Error(`Error: taproot leaf expansion not available`);
        const localEntries = Object.entries(node.expansionMap);
        const localToGlobalPlaceholder = new Map<string, string>();
        for (const [localPlaceholder, keyInfo] of localEntries) {
          const globalPlaceholder = globalPlaceholderFor(keyInfo);
          localToGlobalPlaceholder.set(localPlaceholder, globalPlaceholder);
        }
        remappedMiniscript = remappedMiniscript.replace(
          /@\d+/g,
          placeholder =>
            localToGlobalPlaceholder.get(placeholder) ?? placeholder
        );
        return remappedMiniscript;
      }
      return `{${remapTapTree(node.left)},${remapTapTree(node.right)}}`;
    };

    expandedExpression = `tr(@0,${remapTapTree(expanded.tapTreeInfo)})`;
  }

  if (!expandedExpression || !expansionMap)
    throw new Error(`Error: invalid output`);

  const masterFingerprint = await getMasterFingerprint();

  const allKeys = Object.keys(expansionMap).sort((a, b) => {
    const aIndex = Number(a.slice(1));
    const bIndex = Number(b.slice(1));
    if (Number.isNaN(aIndex) || Number.isNaN(bIndex)) return a.localeCompare(b);
    return aIndex - bIndex;
  });

  const hwwKeys = allKeys.filter(key => {
    const keyMasterFingerprint = expansionMap[key]?.masterFingerprint;
    return (
      keyMasterFingerprint &&
      compare(keyMasterFingerprint, masterFingerprint) === 0
    );
  });
  if (hwwKeys.length === 0) return null;
  if (hwwKeys.length > 1)
    throw new Error(
      `Error: descriptor ${expandedExpression} does not contain exactly 1 hardware wallet key`
    );
  const hwwKey = hwwKeys[0]!;
  const keyMasterFingerprint = expansionMap[hwwKey]!.masterFingerprint;
  const originPath = expansionMap[hwwKey]!.originPath;
  const keyPath = expansionMap[hwwKey]!.keyPath;
  const bip32Like = expansionMap[hwwKey]!.bip32;
  const bip32 = bip32Like ? toBIP32Interface(bip32Like) : undefined;
  if (!keyMasterFingerprint || !originPath || !keyPath || !bip32) {
    throw new Error(
      `Error: hardware wallet key expression must have a valid masterFingerprint: ${keyMasterFingerprint}, originPath: ${originPath}, keyPath: ${keyPath} and a valid bip32 node`
    );
  }
  if (!/^\/[01]\/\d+$/.test(keyPath))
    throw new Error(
      `Error: key paths must be /<1;0>/index, where change is 1 or 0 and index >= 0`
    );
  const [, strChange, strIndex] = keyPath.split('/');
  if (!strChange || !strIndex)
    throw new Error(`Error: invalid hardware wallet key path: ${keyPath}`);
  const change = parseInt(strChange, 10);
  const index = parseInt(strIndex, 10);

  const keyRoots: string[] = [];
  const placeholderToHwwPlaceholder = new Map<string, string>();

  allKeys.forEach((key, index) => {
    if (key !== hwwKey) {
      const otherKeyInfo = expansionMap[key]!;
      if (!otherKeyInfo.bip32) {
        throw new Error(
          `Error: hardware wallet policies only allow xpub-type key expressions`
        );
      }
      if (otherKeyInfo.keyPath !== keyPath) {
        throw new Error(
          `Error: all keyPaths must be the same for this hardware wallet policy: ${otherKeyInfo.keyPath} !== ${keyPath}`
        );
      }
    }
    // The sample Output has one concrete key position, but the device policy
    // represents the whole range. Replace the concrete position with /** here.
    placeholderToHwwPlaceholder.set(key, `@${index}/**`);
    const keyInfo = expansionMap[key]!;
    const keyBip32 = keyInfo.bip32 ? toBIP32Interface(keyInfo.bip32) : null;
    if (keyInfo.masterFingerprint && keyInfo.originPath)
      keyRoots.push(
        `[${toHex(keyInfo.masterFingerprint)}${keyInfo.originPath}]${keyBip32?.neutered().toBase58()}`
      );
    else keyRoots.push(`${keyBip32?.neutered().toBase58()}`);
  });

  const descriptorTemplate = expandedExpression.replace(
    /@\d+/g,
    placeholder => placeholderToHwwPlaceholder.get(placeholder) ?? placeholder
  );

  return { descriptorTemplate, keyRoots, change, index };
}

/** Returns a standard single-key policy for an output, or `null`. */
function compareKeyRoots(arr1: string[], arr2: string[]) {
  if (arr1.length !== arr2.length) {
    return false;
  }
  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false;
    }
  }
  return true;
}

/** Compares policies by descriptor template and key roots only. */
export function samePolicy(policyA: HWWPolicy, policyB: HWWPolicy) {
  return (
    compareKeyRoots(policyA.keyRoots, policyB.keyRoots) &&
    policyA.descriptorTemplate === policyB.descriptorTemplate
  );
}

/** Finds a stored policy matching one derived policy. */
export function findKnownPolicy({
  derivedPolicy,
  knownPolicies
}: {
  derivedPolicy: DerivedHWWPolicy;
  /** Policies already known by the app or registered with the device. */
  knownPolicies?: HWWPolicy[];
}): DerivedHWWPolicy | null {
  const policies = (knownPolicies || []).filter(policy =>
    samePolicy(policy, derivedPolicy)
  );
  if (policies.length > 1) throw new Error(`Error: duplicated policy`);
  if (policies.length === 1) {
    return {
      ...policies[0]!,
      change: derivedPolicy.change,
      index: derivedPolicy.index
    };
  }
  return null;
}
