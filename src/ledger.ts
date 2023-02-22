// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

/*
 * Notes on Ledger implementation:
 *
 * Ledger assumes as external all keyRoots that do not have origin information.
 *
 * Some known Ledger Limitations (based on my tests as of Febr 2023):
 *
 * 1) All keyExpressions must be expanded into @i. In other words,
 * this template is not valid:
 * wsh(and_v(v:pk(03ed0b41d808b012b3a77dd7f6a30c4180dfbcab604133d90ce7593ec7f3e4037b),and_v(v:sha256(6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333),and_v(and_v(v:pk(@0/**),v:pk(@1/**)),older(5)))))
 * (note the fixed 03ed0b41d808b012b3a77dd7f6a30c4180dfbcab604133d90ce7593ec7f3e4037b pubkey)
 *
 * 2) All elements in the keyRoot vector must be xpub-type (no xprv-type, no pubkey-type, ...)
 *
 * 3) All originPaths of the expressions in the keyRoot vector must be the same.
 * On the other hand, an empty originPath is permitted for external keys.
 *
 * 4) Since all originPaths must be the same and originPaths for the Ledger are
 * necessary, a Ledger device can only sign at most 1 key per policy and input.
 *
 * All the conditions above are checked in function descriptorToLedgerFormat.
 */

import type { DescriptorInterface } from './types';
import { AppClient, WalletPolicy } from '@bitcoinerlab/ledger';
import { Network, networks } from 'bitcoinjs-lib';
import { reOriginPath } from './re';

async function ledgerAppInfo(transport: any) {
  const r = await transport.send(0xb0, 0x01, 0x00, 0x00);
  let i = 0;
  const format = r[i++];
  const nameLength = r[i++];
  const name = r.slice(i, (i += nameLength!)).toString('ascii');
  const versionLength = r[i++];
  const version = r.slice(i, (i += versionLength!)).toString('ascii');
  const flagLength = r[i++];
  const flags = r.slice(i, (i += flagLength!));
  return { name, version, flags, format };
}

export async function assertLedgerApp({
  transport,
  name,
  minVersion
}: {
  transport: any;
  name: string;
  minVersion: string;
}): Promise<void> {
  const { name: openName, version } = await ledgerAppInfo(transport);
  if (openName !== name) {
    throw new Error(`Open the ${name} app and try again`);
  } else {
    const [mVmajor, mVminor, mVpatch] = minVersion.split('.').map(Number);
    const [major, minor, patch] = version.split('.').map(Number);
    if (
      mVmajor === undefined ||
      mVminor === undefined ||
      mVpatch === undefined
    ) {
      throw new Error(
        `Pass a minVersion using semver notation: major.minor.patch`
      );
    }
    if (
      major < mVmajor ||
      (major === mVmajor && minor < mVminor) ||
      (major === mVmajor && minor === mVminor && patch < mVpatch)
    )
      throw new Error(`Error: please upgrade ${name} to version ${minVersion}`);
  }
}

function isLedgerStandard({
  ledgerTemplate,
  keyRoots,
  network = networks.bitcoin
}: {
  ledgerTemplate: string;
  keyRoots: string[];
  network?: Network;
}): boolean {
  if (keyRoots.length !== 1) return false;
  const originPath = keyRoots[0]?.match(reOriginPath)?.[1];
  if (!originPath) return false;
  //Network is the 6th character: /44'/0'
  if (originPath[5] !== (network === networks.bitcoin ? '0' : '1'))
    return false;
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

//Standard key expressions don't have name, id or hmac:
export type LedgerPolicy = {
  policyName?: string;
  ledgerTemplate: string;
  keyRoots: string[];
  policyId?: Buffer;
  policyHmac?: Buffer;
};
export type LedgerState = {
  masterFingerprint?: Buffer;
  policies?: LedgerPolicy[];
  xpubs?: { [key: string]: string };
};

export async function getLedgerMasterFingerPrint({
  ledgerClient,
  ledgerState
}: {
  ledgerClient: AppClient;
  ledgerState: LedgerState;
}): Promise<Buffer> {
  let masterFingerprint = ledgerState.masterFingerprint;
  if (!masterFingerprint) {
    masterFingerprint = Buffer.from(
      await ledgerClient.getMasterFingerprint(),
      'hex'
    );
    ledgerState.masterFingerprint = masterFingerprint;
  }
  return masterFingerprint;
}
export async function getLedgerXpub({
  originPath,
  ledgerClient,
  ledgerState
}: {
  originPath: string;
  ledgerClient: AppClient;
  ledgerState: LedgerState;
}): Promise<string> {
  if (!ledgerState.xpubs) ledgerState.xpubs = {};
  let xpub = ledgerState.xpubs[originPath];
  if (!xpub) {
    try {
      //Try getting the xpub without user confirmation
      xpub = await ledgerClient.getExtendedPubkey(`m${originPath}`, false);
    } catch (err) {
      xpub = await ledgerClient.getExtendedPubkey(`m${originPath}`, true);
    }
    ledgerState.xpubs[originPath] = xpub;
  }
  return xpub;
}

/**
 * Takes a descriptor and gets its Ledger Wallet Policy, that is, its keyRoots and template.
 * keyRoots and template follow Ledger's specifications:
 * https://github.com/LedgerHQ/app-bitcoin-new/blob/develop/doc/wallet.md
 *
 * keyRoots and template are a generalization of a descriptor and serve to
 * describe internal and external addresses and any index.
 *
 * So, this function starts from a descriptor and obtains generalized Ledger
 * wallet policy.
 *
 * keyRoots is an array of strings, encoding xpub-type key expressions up to the origin.
 * F.ex.: [76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF
 *
 * Template encodes the descriptor script expression, where its key
 * expressions are represented using variables for each keyRoot and finished with "/**"
 * (for change 1 or 0 and any index). F.ex.:
 * wsh(sortedmulti(2,@0/**,@1/**)), where @0 corresponds the first element in the keyRoots array.
 *
 * If this descriptor does not contain any key that can be signed with the ledger
 * (non-matching masterFingerprint), then this function returns null.
 *
 * This function takes into account all the considerations regarding Ledger
 * policy implementation details expressed in the header of this file.
 */
export async function descriptorToLedgerFormat({
  descriptor,
  ledgerClient,
  ledgerState
}: {
  descriptor: DescriptorInterface;
  ledgerClient: AppClient;
  ledgerState: LedgerState;
}): Promise<{ ledgerTemplate: string; keyRoots: string[] } | null> {
  const expandedExpression = descriptor.expand().expandedExpression;
  const expansionMap = descriptor.expand().expansionMap;
  if (!expandedExpression || !expansionMap)
    throw new Error(`Error: invalid descriptor`);

  const ledgerMasterFingerprint = await getLedgerMasterFingerPrint({
    ledgerClient,
    ledgerState
  });

  //It's important to have keys sorted in ascii order. keys
  //are of this type: @0, @1, @2, ....  and they also appear in the expandedExpression
  //in ascending ascii order. Note that Object.keys(expansionMap ) does not ensure
  //that the order is respected and so we force it.
  const allKeys = Object.keys(expansionMap).sort();

  const ledgerKeys = allKeys.filter(key => {
    const masterFingerprint = expansionMap[key]?.masterFingerprint;
    return (
      masterFingerprint &&
      Buffer.compare(masterFingerprint, ledgerMasterFingerprint) === 0
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
  const bip32 = expansionMap[ledgerKey]!.bip32;
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
  let ledgerTemplate = expandedExpression;

  allKeys.forEach(key => {
    if (key !== ledgerKey) {
      //This block here only does data integrity assertions:
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
    ledgerTemplate = ledgerTemplate.replaceAll(key, `@${keyRoots.length}/**`);
    const keyInfo = expansionMap[key]!;
    if (keyInfo.masterFingerprint && keyInfo.originPath)
      keyRoots.push(
        `[${keyInfo.masterFingerprint?.toString('hex')}${
          keyInfo.originPath
        }]${keyInfo?.bip32?.neutered().toBase58()}`
      );
    else keyRoots.push(`${keyInfo?.bip32?.neutered().toBase58()}`);
  });

  return { ledgerTemplate, keyRoots };
}

/**
 * It registers a policy based on a descriptor. It stores it in ledgerState.
 *
 * If the policy was already registered, it does not register it.
 * If the policy is standard, it does not register it.
 *
 **/
export async function registerLedgerWallet({
  descriptor,
  ledgerClient,
  ledgerState,
  policyName
}: {
  descriptor: DescriptorInterface;
  ledgerClient: AppClient;
  ledgerState: LedgerState;
  policyName: string;
}) {
  const result = await descriptorToLedgerFormat({
    descriptor,
    ledgerClient,
    ledgerState
  });
  if (await ledgerPolicyFromStandard({ descriptor, ledgerClient, ledgerState }))
    return;
  if (!result)
    throw new Error(`Error: descriptor does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (!ledgerState.policies) ledgerState.policies = [];
  let walletPolicy, policyHmac;
  //Search in ledgerState first
  const policy = await ledgerPolicyFromState({
    descriptor,
    ledgerClient,
    ledgerState
  });
  if (policy) {
    if (policy.policyName !== policyName)
      throw new Error(
        `Error: policy was already registered with a different name: ${policy.policyName}`
      );
    //It already existed. No need to register it again.
  } else {
    walletPolicy = new WalletPolicy(policyName, ledgerTemplate, keyRoots);
    let policyId;
    [policyId, policyHmac] = await ledgerClient.registerWallet(walletPolicy);
    const policy: LedgerPolicy = {
      policyName,
      ledgerTemplate,
      keyRoots,
      policyId,
      policyHmac
    };
    ledgerState.policies.push(policy);
  }
}
/**
 * Retrieve a standard ledger policy or null if it does correspond.
 **/
export async function ledgerPolicyFromStandard({
  descriptor,
  ledgerClient,
  ledgerState
}: {
  descriptor: DescriptorInterface;
  ledgerClient: AppClient;
  ledgerState: LedgerState;
}): Promise<LedgerPolicy | null> {
  const result = await descriptorToLedgerFormat({
    descriptor,
    ledgerClient,
    ledgerState
  });
  if (!result)
    throw new Error(`Error: descriptor does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (
    isLedgerStandard({
      ledgerTemplate,
      keyRoots,
      network: descriptor.getNetwork()
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

/**
 * Retrieve a ledger policy from ledgerState or null if it does not exist yet.
 **/
export async function ledgerPolicyFromState({
  descriptor,
  ledgerClient,
  ledgerState
}: {
  descriptor: DescriptorInterface;
  ledgerClient: AppClient;
  ledgerState: LedgerState;
}): Promise<LedgerPolicy | null> {
  const result = await descriptorToLedgerFormat({
    descriptor,
    ledgerClient,
    ledgerState
  });
  if (!result)
    throw new Error(`Error: descriptor does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (!ledgerState.policies) ledgerState.policies = [];
  //Search in ledgerState:
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
