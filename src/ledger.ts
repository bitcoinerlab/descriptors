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
 * All the conditions above are checked in function ledgerPolicyFromOutput.
 */

import {
  DescriptorInstance,
  OutputInstance,
  DescriptorsFactory
} from './descriptors';
import { Network, networks, Psbt, Transaction } from 'bitcoinjs-lib';
import { reOriginPath } from './re';
import type { TinySecp256k1Interface } from './types';

/**
 * Dynamically imports the 'ledger-bitcoin' module and, if provided, checks if `ledgerClient` is an instance of `AppClient`.
 *
 * @async
 * @param {unknown} ledgerClient - An optional parameter that, if provided, is checked to see if it's an instance of `AppClient`.
 * @throws {Error} Throws an error if `ledgerClient` is provided but is not an instance of `AppClient`.
 * @throws {Error} Throws an error if the 'ledger-bitcoin' module cannot be imported. This typically indicates that the 'ledger-bitcoin' peer dependency is not installed.
 * @returns {Promise<unknown>} Returns a promise that resolves with the entire 'ledger-bitcoin' module if it can be successfully imported. We force it to return an unknown type so that the declaration of this function won't break projects that don't use ledger-bitcoin as dependency
 *
 * @example
 *
 * importAndValidateLedgerBitcoin(ledgerClient)
 *   .then((module) => {
 *     const { AppClient, PsbtV2, DefaultWalletPolicy, WalletPolicy, DefaultDescriptorTemplate, PartialSignature } = module;
 *     // Use the imported objects...
 *   })
 *   .catch((error) => console.error(error));
 */
export async function importAndValidateLedgerBitcoin(
  ledgerClient?: unknown
): Promise<unknown> {
  let ledgerBitcoinModule;
  try {
    // Originally, the code used dynamic imports:
    // ledgerBitcoinModule = await import('ledger-bitcoin');

    // However, in React Native with the Metro bundler, there's an issue with
    // recognizing dynamic imports inside try-catch blocks. For details, refer to:
    // https://github.com/react-native-community/discussions-and-proposals/issues/120

    // The dynamic import gets transpiled to:
    // ledgerBitcoinModule = Promise.resolve().then(() => __importStar(require('ledger-bitcoin')));

    // Metro bundler fails to recognize the above as conditional. Hence, it tries
    // to require 'ledger-bitcoin' unconditionally, leading to potential errors if
    // 'ledger-bitcoin' is not installed (given it's an optional peerDependency).

    // To bypass this, we directly use require:
    ledgerBitcoinModule = require('ledger-bitcoin');
  } catch (error) {
    throw new Error(
      'Could not import "ledger-bitcoin". This is a peer dependency and needs to be installed explicitly. Please run "npm install ledger-bitcoin" to use Ledger Hardware Wallet functionality.'
    );
  }
  const { AppClient } = ledgerBitcoinModule;
  if (ledgerClient !== undefined && !(ledgerClient instanceof AppClient)) {
    throw new Error('Error: invalid AppClient instance');
  }
  return ledgerBitcoinModule;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
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

/**
 * Verifies if the Ledger device is connected, if the required Bitcoin App is opened,
 * and if the version of the app meets the minimum requirements.
 *
 * @throws Will throw an error if the Ledger device is not connected, the required
 * Bitcoin App is not opened, or if the version is below the required number.
 *
 * @returns Promise<void> - A promise that resolves if all assertions pass, or throws otherwise.
 */
export async function assertLedgerApp({
  transport,
  name,
  minVersion
}: {
  /**
   * Connection transport with the Ledger device.
   * One of these: https://github.com/LedgerHQ/ledger-live#libs---libraries
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transport: any;
  /**
   * The name of the Bitcoin App. "Bitcoin" for mainnet or "Bitcoin Test" for testnet.
   */
  name: string;
  /**
   * The minimum acceptable version of the Bitcoin App in semver format (major.minor.patch).
   */
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
/**
 * Ledger devices operate in a state-less manner. Therefore, policy information
 * needs to be maintained in a separate data structure, `ledgerState`. For optimization,
 * `ledgerState` also stores cached xpubs and the masterFingerprint.
 */
export type LedgerState = {
  masterFingerprint?: Buffer;
  policies?: LedgerPolicy[];
  xpubs?: { [key: string]: string };
};

export type LedgerManager = {
  ledgerClient: unknown;
  ledgerState: LedgerState;
  ecc: TinySecp256k1Interface;
  network: Network;
};

/** Retrieves the masterFingerPrint of a Ledger device */
export async function getLedgerMasterFingerPrint({
  ledgerManager
}: {
  ledgerManager: LedgerManager;
}): Promise<Buffer>;

/** @deprecated @hidden */
export async function getLedgerMasterFingerPrint({
  ledgerClient,
  ledgerState
}: {
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<Buffer>;

/** @hidden */
export async function getLedgerMasterFingerPrint({
  ledgerClient,
  ledgerState,
  ledgerManager
}: {
  ledgerClient?: unknown;
  ledgerState?: LedgerState;
  ledgerManager?: LedgerManager;
}): Promise<Buffer> {
  if (ledgerManager && (ledgerClient || ledgerState))
    throw new Error(`ledgerClient and ledgerState have been deprecated`);
  if (ledgerManager) ({ ledgerClient, ledgerState } = ledgerManager);
  if (!ledgerClient || !ledgerState)
    throw new Error(`Could not retrieve ledgerClient or ledgerState`);
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    ledgerClient
  )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);
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

/** Retrieves the xpub of a certain originPath of a Ledger device */
export async function getLedgerXpub({
  originPath,
  ledgerManager
}: {
  originPath: string;
  ledgerManager: LedgerManager;
}): Promise<string>;

/** @deprecated @hidden */
export async function getLedgerXpub({
  originPath,
  ledgerClient,
  ledgerState
}: {
  originPath: string;
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<string>;

/** @hidden */
export async function getLedgerXpub({
  originPath,
  ledgerClient,
  ledgerState,
  ledgerManager
}: {
  originPath: string;
  ledgerClient?: unknown;
  ledgerState?: LedgerState;
  ledgerManager?: LedgerManager;
}): Promise<string> {
  if (ledgerManager && (ledgerClient || ledgerState))
    throw new Error(`ledgerClient and ledgerState have been deprecated`);
  if (ledgerManager) ({ ledgerClient, ledgerState } = ledgerManager);
  if (!ledgerClient || !ledgerState)
    throw new Error(`Could not retrieve ledgerClient or ledgerState`);
  const { AppClient } = (await importAndValidateLedgerBitcoin(
    ledgerClient
  )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);
  if (!ledgerState.xpubs) ledgerState.xpubs = {};
  let xpub = ledgerState.xpubs[originPath];
  if (!xpub) {
    try {
      //Try getting the xpub without user confirmation
      xpub = await ledgerClient.getExtendedPubkey(`m${originPath}`, false);
    } catch (err) {
      xpub = await ledgerClient.getExtendedPubkey(`m${originPath}`, true);
    }
    if (typeof xpub !== 'string')
      throw new Error(`Error: ledgerClient did not return a valid xpub`);
    ledgerState.xpubs[originPath] = xpub;
  }
  return xpub;
}

/**
 * Checks whether there is a policy in ledgerState that the ledger
 * could use to sign this psbt input.
 *
 * It found return the policy, otherwise, return undefined
 *
 * All considerations in the header of this file are applied
 */
export async function ledgerPolicyFromPsbtInput({
  ledgerManager,
  psbt,
  index
}: {
  ledgerManager: LedgerManager;
  psbt: Psbt;
  index: number;
}) {
  const { ledgerState, ledgerClient, ecc, network } = ledgerManager;

  const { Output } = DescriptorsFactory(ecc);
  const input = psbt.data.inputs[index];
  if (!input) throw new Error(`Input numer ${index} not set.`);
  let scriptPubKey: Buffer | undefined;
  if (input.nonWitnessUtxo) {
    const vout = psbt.txInputs[index]?.index;
    if (vout === undefined)
      throw new Error(
        `Could not extract vout from nonWitnessUtxo for input ${index}.`
      );
    scriptPubKey = Transaction.fromBuffer(input.nonWitnessUtxo).outs[vout]
      ?.script;
  } else if (input.witnessUtxo) {
    scriptPubKey = input.witnessUtxo.script;
  }
  if (!scriptPubKey)
    throw new Error(`Could not retrieve scriptPubKey for input ${index}.`);

  const bip32Derivations = input.bip32Derivation;
  if (!bip32Derivations || !bip32Derivations.length)
    throw new Error(`Input ${index} does not contain bip32 derivations.`);

  const ledgerMasterFingerprint = await getLedgerMasterFingerPrint({
    ledgerManager
  });
  for (const bip32Derivation of bip32Derivations) {
    //get the keyRoot and keyPath. If it matches one of our policies then
    //we are still not sure this is the policy that must be used yet
    //So we must use the template and the keyRoot of each policy and compute the
    //scriptPubKey:
    if (
      Buffer.compare(
        bip32Derivation.masterFingerprint,
        ledgerMasterFingerprint
      ) === 0
    ) {
      // Match /m followed by n consecutive hardened levels and then 2 consecutive unhardened levels:
      const match = bip32Derivation.path.match(/m((\/\d+['hH])*)(\/\d+\/\d+)?/);
      const originPath = match ? match[1] : undefined; //n consecutive hardened levels
      const keyPath = match ? match[3] : undefined; //2 unhardened levels or undefined

      if (originPath && keyPath) {
        const [, strChange, strIndex] = keyPath.split('/');
        if (!strChange || !strIndex)
          throw new Error(`keyPath ${keyPath} incorrectly extracted`);
        const change = parseInt(strChange, 10);
        const index = parseInt(strIndex, 10);

        const coinType = network === networks.bitcoin ? 0 : 1;

        //standard policy candidate. This policy will be added to the pool
        //of policies below and check if it produces the correct scriptPubKey
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
            const xpub = await getLedgerXpub({
              originPath,
              ledgerClient,
              ledgerState
            });
            standardPolicy = {
              ledgerTemplate: standardTemplate,
              keyRoots: [
                `[${ledgerMasterFingerprint.toString(
                  'hex'
                )}${originPath}]${xpub}`
              ]
            };
          }
        }

        const policies = [...(ledgerState.policies || [])];
        if (standardPolicy) policies.push(standardPolicy);

        for (const policy of policies) {
          //Build the descriptor from the ledgerTemplate + keyRoots
          //then get the scriptPubKey
          let descriptor: string | undefined = policy.ledgerTemplate;
          // Replace change (making sure the value in the change level for the
          // template of the policy meets the change in bip32Derivation):
          descriptor = descriptor.replace(/\/\*\*/g, `/<0;1>/*`);
          const regExpMN = new RegExp(`/<(\\d+);(\\d+)>`, 'g');
          let matchMN;
          while (descriptor && (matchMN = regExpMN.exec(descriptor)) !== null) {
            const [M, N] = [
              parseInt(matchMN[1]!, 10),
              parseInt(matchMN[2]!, 10)
            ];
            if (M === change || N === change)
              descriptor = descriptor.replace(`/<${M};${N}>`, `/${change}`);
            else descriptor = undefined;
          }
          if (descriptor) {
            // Replace index:
            descriptor = descriptor.replace(/\/\*/g, `/${index}`);
            // Replace origin in reverse order to prevent
            // misreplacements, e.g., @10 being mistaken for @1 and leaving a 0.
            for (let i = policy.keyRoots.length - 1; i >= 0; i--) {
              const keyRoot = policy.keyRoots[i];
              if (!keyRoot)
                throw new Error(`keyRoot ${keyRoot} invalidly extracted.`);
              const match = keyRoot.match(/\[([^]+)\]/);
              const keyRootOrigin = match && match[1];
              if (keyRootOrigin) {
                const [, ...arrKeyRootOriginPath] = keyRootOrigin.split('/');
                const keyRootOriginPath = '/' + arrKeyRootOriginPath.join('/');
                //We check all origins to be the same even if they do not
                //belong to the ledger (read the header in this file)
                if (descriptor && keyRootOriginPath === originPath)
                  descriptor = descriptor.replace(
                    new RegExp(`@${i}`, 'g'),
                    keyRoot
                  );
                else descriptor = undefined;
              } else descriptor = undefined;
            }

            //verify the scriptPubKey from the input vs. the one obtained from
            //the policy after having filled in the keyPath in the template
            if (descriptor) {
              const policyScriptPubKey = new Output({
                descriptor,
                network
              }).getScriptPubKey();

              if (Buffer.compare(policyScriptPubKey, scriptPubKey) === 0) {
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

/**
 * Given an output, it extracts its descriptor and converts it to a Ledger
 * Wallet Policy, that is, its keyRoots and template.
 *
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
export async function ledgerPolicyFromOutput({
  output,
  ledgerClient,
  ledgerState
}: {
  output: OutputInstance;
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<{ ledgerTemplate: string; keyRoots: string[] } | null> {
  const expandedExpression = output.expand().expandedExpression;
  const expansionMap = output.expand().expansionMap;
  if (!expandedExpression || !expansionMap)
    throw new Error(`Error: invalid output`);

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
 * Registers a policy based on a provided descriptor.
 *
 * This function will:
 * 1. Store the policy in `ledgerState` inside the `ledgerManager`.
 * 2. Avoid re-registering if the policy was previously registered.
 * 3. Skip registration if the policy is considered "standard".
 *
 * It's important to understand the nature of the Ledger Policy being registered:
 * - While a descriptor might point to a specific output index of a particular change address,
 *   the corresponding Ledger Policy abstracts this and represents potential outputs for
 *   all addresses (both external and internal).
 * - This means that the registered Ledger Policy is a generalized version of the descriptor,
 *   not assuming specific values for the keyPath.
 *
 */
export async function registerLedgerWallet({
  descriptor,
  ledgerManager,
  policyName
}: {
  descriptor: string;
  ledgerManager: LedgerManager;
  /** The Name we want to assign to this specific policy */
  policyName: string;
}): Promise<void>;

/**
 * @deprecated
 * @hidden
 */
export async function registerLedgerWallet({
  descriptor,
  ledgerClient,
  ledgerState,
  policyName
}: {
  descriptor: DescriptorInstance;
  ledgerClient: unknown;
  ledgerState: LedgerState;
  policyName: string;
}): Promise<void>;

/**
 * To be removed in v3.0 and replaced by a version that does not accept
 * descriptors
 * @hidden
 **/
export async function registerLedgerWallet({
  descriptor,
  ledgerClient,
  ledgerState,
  ledgerManager,
  policyName
}: {
  descriptor: DescriptorInstance | string;
  ledgerClient?: unknown;
  ledgerState?: LedgerState;
  ledgerManager?: LedgerManager;
  policyName: string;
}) {
  if (typeof descriptor !== 'string' && ledgerManager)
    throw new Error(`Invalid usage: descriptor must be a string`);
  if (ledgerManager && (ledgerClient || ledgerState))
    throw new Error(
      `Invalid usage: either ledgerManager or ledgerClient + ledgerState`
    );
  if (ledgerManager) ({ ledgerClient, ledgerState } = ledgerManager);
  if (!ledgerClient) throw new Error(`ledgerManager not provided`);
  if (!ledgerState) throw new Error(`ledgerManager not provided`);
  const { WalletPolicy, AppClient } = (await importAndValidateLedgerBitcoin(
    ledgerClient
  )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  let output: OutputInstance;
  if (typeof descriptor === 'string') {
    if (!ledgerManager) throw new Error(`ledgerManager not provided`);
    const { Output } = DescriptorsFactory(ledgerManager.ecc);
    output = new Output({
      descriptor,
      ...(descriptor.includes('*') ? { index: 0 } : {}), //if ranged set any index
      network: ledgerManager.network
    });
  } else output = descriptor;
  if (await ledgerPolicyFromStandard({ output, ledgerClient, ledgerState }))
    return;
  const result = await ledgerPolicyFromOutput({
    output,
    ledgerClient,
    ledgerState
  });
  if (await ledgerPolicyFromStandard({ output, ledgerClient, ledgerState }))
    return;
  if (!result) throw new Error(`Error: output does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;
  if (!ledgerState.policies) ledgerState.policies = [];
  let walletPolicy, policyHmac;
  //Search in ledgerState first
  const policy = await ledgerPolicyFromState({
    output,
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
  output,
  ledgerClient,
  ledgerState
}: {
  output: OutputInstance;
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<LedgerPolicy | null> {
  const result = await ledgerPolicyFromOutput({
    output,
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

/**
 * Retrieve a ledger policy from ledgerState or null if it does not exist yet.
 **/
export async function ledgerPolicyFromState({
  output,
  ledgerClient,
  ledgerState
}: {
  output: OutputInstance;
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<LedgerPolicy | null> {
  const result = await ledgerPolicyFromOutput({
    output,
    ledgerClient,
    ledgerState
  });
  if (!result) throw new Error(`Error: output does not have a ledger input`);
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
