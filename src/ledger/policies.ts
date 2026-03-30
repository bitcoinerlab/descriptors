// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { OutputInstance } from '../descriptors';
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
import { getLedgerMasterFingerPrint, getLedgerXpub } from './client';
import type { LedgerManager } from './index';

export type LedgerPolicy = {
  policyName?: string;
  ledgerTemplate: string;
  keyRoots: string[];
  policyId?: Uint8Array;
  policyHmac?: Uint8Array;
};

function isLedgerStandard({
  ledgerTemplate,
  keyRoots,
  network
}: {
  ledgerTemplate: string;
  keyRoots: string[];
  network: Network;
}): boolean {
  if (keyRoots.length !== 1) return false;
  const originPath = keyRoots[0]?.match(reOriginPath)?.[1];
  if (!originPath) return false;
  const originCoinType = originPath.match(/^\/\d+'\/([01])'/)?.[1];
  if (!originCoinType) return false;
  if (originCoinType !== `${coinTypeFromNetwork(network)}`) return false;
  if (
    (ledgerTemplate === 'pkh(@0/**)' &&
      originPath.match(/^\/44'\/[01]'\/(\d+)'$/)) ||
    (ledgerTemplate === 'wpkh(@0/**)' &&
      originPath.match(/^\/84'\/[01]'\/(\d+)'$/)) ||
    (ledgerTemplate === 'sh(wpkh(@0/**))' &&
      originPath.match(/^\/49'\/[01]'\/(\d+)'$/)) ||
    (ledgerTemplate === 'tr(@0/**)' &&
      originPath.match(/^\/86'\/[01]'\/(\d+)'$/))
  )
    return true;
  return false;
}

export async function ledgerPolicyFromPsbtInput({
  ledgerManager,
  psbt,
  index
}: {
  ledgerManager: LedgerManager;
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
}) {
  const bitcoinLib = getBitcoinLibOrThrow();
  psbt = toPsbt(psbt);
  const { ledgerState, network, Output } = ledgerManager;
  const { Transaction } = bitcoinLib;
  const input = psbt.data.inputs[index];
  if (!input) throw new Error(`Error: input ${index} not available`);
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

  const keyDerivations = [
    ...(input.bip32Derivation || []),
    ...(input.tapBip32Derivation || [])
  ];
  if (keyDerivations.length === 0)
    throw new Error(
      `Input ${index} does not contain bip32 or tapBip32 derivations.`
    );

  const ledgerMasterFingerprint = await getLedgerMasterFingerPrint({
    ledgerManager
  });
  for (const keyDerivation of keyDerivations) {
    if (
      compare(keyDerivation.masterFingerprint, ledgerMasterFingerprint) === 0
    ) {
      const match = keyDerivation.path.match(/m((\/\d+['hH])*)(\/\d+\/\d+)?/);
      const originPath = match ? match[1] : undefined;
      const keyPath = match ? match[3] : undefined;

      if (originPath && keyPath) {
        const [, strChange, strIndex] = keyPath.split('/');
        if (!strChange || !strIndex)
          throw new Error(`keyPath ${keyPath} incorrectly extracted`);
        const change = parseInt(strChange, 10);
        const index = parseInt(strIndex, 10);

        const coinType = coinTypeFromNetwork(network);

        let standardPolicy;
        if (change === 0 || change === 1) {
          const standardTemplate = originPath.match(
            new RegExp(`^/44'/${coinType}'/(\\d+)'$`)
          )
            ? 'pkh(@0/**)'
            : originPath.match(new RegExp(`^/84'/${coinType}'/(\\d+)'$`))
              ? 'wpkh(@0/**)'
              : originPath.match(new RegExp(`^/49'/${coinType}'/(\\d+)'$`))
                ? 'sh(wpkh(@0/**))'
                : originPath.match(new RegExp(`^/86'/${coinType}'/(\\d+)'$`))
                  ? 'tr(@0/**)'
                  : undefined;
          if (standardTemplate) {
            const xpub = await getLedgerXpub({ originPath, ledgerManager });
            standardPolicy = {
              ledgerTemplate: standardTemplate,
              keyRoots: [
                `[${toHex(ledgerMasterFingerprint)}${originPath}]${xpub}`
              ]
            };
          }
        }

        const policies = [...(ledgerState.policies || [])];
        if (standardPolicy) policies.push(standardPolicy);

        for (const policy of policies) {
          let descriptor: string | undefined = policy.ledgerTemplate;
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
              const match = keyRoot.match(/\[([^]+)\]/);
              const keyRootOrigin = match && match[1];
              if (keyRootOrigin) {
                const [, ...arrKeyRootOriginPath] = keyRootOrigin.split('/');
                const keyRootOriginPath = '/' + arrKeyRootOriginPath.join('/');
                if (descriptor && keyRootOriginPath === originPath)
                  descriptor = descriptor.replace(
                    new RegExp(`@${i}`, 'g'),
                    keyRoot
                  );
                else descriptor = undefined;
              } else {
                if (descriptor)
                  descriptor = descriptor.replace(
                    new RegExp(`@${i}`, 'g'),
                    keyRoot
                  );
              }
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

export async function ledgerPolicyFromOutput({
  output,
  ledgerManager
}: {
  output: OutputInstance;
  ledgerManager: LedgerManager;
}): Promise<{ ledgerTemplate: string; keyRoots: string[] } | null> {
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

  const ledgerMasterFingerprint = await getLedgerMasterFingerPrint({
    ledgerManager
  });

  const allKeys = Object.keys(expansionMap).sort((a, b) => {
    const aIndex = Number(a.slice(1));
    const bIndex = Number(b.slice(1));
    if (Number.isNaN(aIndex) || Number.isNaN(bIndex)) return a.localeCompare(b);
    return aIndex - bIndex;
  });

  const ledgerKeys = allKeys.filter(key => {
    const masterFingerprint = expansionMap[key]?.masterFingerprint;
    return (
      masterFingerprint &&
      compare(masterFingerprint, ledgerMasterFingerprint) === 0
    );
  });
  if (ledgerKeys.length === 0) return null;
  if (ledgerKeys.length > 1)
    throw new Error(
      `Error: descriptor ${expandedExpression} does not contain exactly 1 ledger key`
    );
  const ledgerKey = ledgerKeys[0]!;
  const masterFingerprint = expansionMap[ledgerKey]!.masterFingerprint;
  const originPath = expansionMap[ledgerKey]!.originPath;
  const keyPath = expansionMap[ledgerKey]!.keyPath;
  const bip32Like = expansionMap[ledgerKey]!.bip32;
  const bip32 = bip32Like ? toBIP32Interface(bip32Like) : undefined;
  if (!masterFingerprint || !originPath || !keyPath || !bip32) {
    throw new Error(
      `Error: Ledger key expression must have a valid masterFingerprint: ${masterFingerprint}, originPath: ${originPath}, keyPath: ${keyPath} and a valid bip32 node`
    );
  }
  if (!/^\/[01]\/\d+$/.test(keyPath))
    throw new Error(
      `Error: key paths must be /<1;0>/index, where change is 1 or 0 and index >= 0`
    );

  const keyRoots: string[] = [];
  const placeholderToLedgerPlaceholder = new Map<string, string>();

  allKeys.forEach((key, index) => {
    if (key !== ledgerKey) {
      const otherKeyInfo = expansionMap[key]!;
      if (!otherKeyInfo.bip32) {
        throw new Error(`Error: ledger only allows xpub-type key expressions`);
      }
      if (otherKeyInfo.originPath) {
        if (otherKeyInfo.originPath !== originPath) {
          throw new Error(
            `Error: all originPaths must be the same for Ledger being able to sign. On the other hand, you can leave the origin info empty for external keys: ${otherKeyInfo.originPath} !== ${originPath}`
          );
        }
      }
      if (otherKeyInfo.keyPath !== keyPath) {
        throw new Error(
          `Error: all keyPaths must be the same for Ledger being able to sign: ${otherKeyInfo.keyPath} !== ${keyPath}`
        );
      }
    }
    placeholderToLedgerPlaceholder.set(key, `@${index}/**`);
    const keyInfo = expansionMap[key]!;
    const keyBip32 = keyInfo.bip32 ? toBIP32Interface(keyInfo.bip32) : null;
    if (keyInfo.masterFingerprint && keyInfo.originPath)
      keyRoots.push(
        `[${toHex(keyInfo.masterFingerprint)}${keyInfo.originPath}]${keyBip32?.neutered().toBase58()}`
      );
    else keyRoots.push(`${keyBip32?.neutered().toBase58()}`);
  });

  const ledgerTemplate = expandedExpression.replace(
    /@\d+/g,
    placeholder =>
      placeholderToLedgerPlaceholder.get(placeholder) ?? placeholder
  );

  return { ledgerTemplate, keyRoots };
}

export async function ledgerPolicyFromStandard({
  output,
  ledgerManager
}: {
  output: OutputInstance;
  ledgerManager: LedgerManager;
}): Promise<LedgerPolicy | null> {
  const result = await ledgerPolicyFromOutput({
    output,
    ledgerManager
  });
  if (!result)
    throw new Error(`Error: descriptor does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (
    isLedgerStandard({
      ledgerTemplate,
      keyRoots,
      network: output.getNetwork()
    })
  )
    return { ledgerTemplate, keyRoots };
  return null;
}

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

export function comparePolicies(policyA: LedgerPolicy, policyB: LedgerPolicy) {
  return (
    compareKeyRoots(policyA.keyRoots, policyB.keyRoots) &&
    policyA.ledgerTemplate === policyB.ledgerTemplate
  );
}

export async function ledgerPolicyFromState({
  output,
  ledgerManager
}: {
  output: OutputInstance;
  ledgerManager: LedgerManager;
}): Promise<LedgerPolicy | null> {
  const { ledgerState } = ledgerManager;
  const result = await ledgerPolicyFromOutput({
    output,
    ledgerManager
  });
  if (!result) throw new Error(`Error: output does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (!ledgerState.policies) ledgerState.policies = [];
  const policies = ledgerState.policies.filter(policy =>
    comparePolicies(policy, { ledgerTemplate, keyRoots })
  );
  if (policies.length > 1) throw new Error(`Error: duplicated policy`);
  if (policies.length === 1) {
    return policies[0]!;
  } else {
    return null;
  }
}
