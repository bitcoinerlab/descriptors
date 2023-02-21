import type { DescriptorInterface } from './types';
import { AppClient, WalletPolicy } from 'ledger';

export type DefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';

function isDefaultDescriptorTemplate(
  str: string
): str is DefaultDescriptorTemplate {
  return ['pkh(@0/**)', 'sh(wpkh(@0/**))', 'wpkh(@0/**)', 'tr(@0/**)'].includes(
    str
  );
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

  const ledgerKeys = Object.keys(expansionMap).filter(key => {
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

  const ledgerKey = ledgerKeys[0];
  if (!ledgerKey) throw new Error(`Error: invalid ledger key ${ledgerKey}`);
  const ledgerKeyInfo = expansionMap[ledgerKey];
  if (!ledgerKeyInfo?.originPath)
    throw new Error(`Error: invalid ledger originPath`);
  if (!ledgerKeyInfo?.keyPath || !/^\/[01]\/\d+$/.test(ledgerKeyInfo?.keyPath))
    throw new Error(
      `Error: key paths must be /<1;0>/index, where change is 1 or 0 and index >= 0`
    );

  const otherKeys = Object.keys(expansionMap).filter(
    key =>
      expansionMap[key]?.originPath === ledgerKeyInfo.originPath &&
      expansionMap[key]?.keyPath === ledgerKeyInfo.keyPath
  );

  const keyRoots: string[] = [];
  let ledgerTemplate = expandedExpression;

  Object.keys(expansionMap).forEach(key => {
    if (key === ledgerKey || otherKeys.includes(key)) {
      ledgerTemplate = ledgerTemplate.replaceAll(key, `@${keyRoots.length}/**`);
      const keyInfo = expansionMap[key]!;
      keyRoots.push(
        `[${keyInfo.masterFingerprint?.toString('hex')}${
          keyInfo.originPath
        }]${keyInfo?.bip32?.neutered().toBase58()}`
      );
    } else {
      ledgerTemplate = ledgerTemplate.replaceAll(
        key,
        expansionMap[key]!.keyExpression
      );
    }
  });

  return { ledgerTemplate, keyRoots };
}

/**
 * It registers a policy based on a descriptor. It stores it in ledgerState.
 *
 * If the policy was already registered, it does not register it.
 *
 **/
export async function registerLedgerPolicy({
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

  if (isDefaultDescriptorTemplate(ledgerTemplate)) {
    if (keyRoots.length !== 1)
      throw new Error(
        `Error: there should be only 1 key roots for a standard policy`
      );
    //TODO: This should now assert that the originPath follows the standard convention 44/84/49
    //wrt the default descriptor & network. Get the network from the descriptor
    return { ledgerTemplate, keyRoots };
  }
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
