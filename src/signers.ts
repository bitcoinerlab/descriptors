// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { isTaprootInput } from 'bitcoinjs-lib/src/psbt/bip371';
import { tapTweakHash } from 'bitcoinjs-lib/src/payments/bip341';
import type { Psbt } from 'bitcoinjs-lib';

import type { ECPairInterface } from 'ecpair';
import type { BIP32Interface } from 'bip32';
import type { DescriptorInstance } from './descriptors';
import {
  importAndValidateLedgerBitcoin,
  comparePolicies,
  LedgerPolicy,
  ledgerPolicyFromState,
  ledgerPolicyFromStandard,
  ledgerPolicyFromOutput,
  LedgerState,
  LedgerManager,
  ledgerPolicyFromPsbtInput
} from './ledger';
import { applyPR2137 } from './applyPR2137';
type DefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';
declare class PartialSignature {
  readonly pubkey: Buffer;
  readonly signature: Buffer;
  readonly tapleafHash?: Buffer;
  constructor(pubkey: Buffer, signature: Buffer, tapleafHash?: Buffer);
}

function range(n: number): number[] {
  return [...Array(n).keys()];
}
export function signInputECPair({
  psbt,
  index,
  ecpair
}: {
  psbt: Psbt;
  index: number;
  ecpair: ECPairInterface;
}): void {
  //psbt.signInput(index, ecpair); <- Replaced for the code below
  //that can handle taroot inputs automatically.
  //See https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
  const input = psbt.data.inputs[index];
  if (!input) throw new Error('Invalid index');
  if (isTaprootInput(input)) {
    const hash = tapTweakHash(
      Buffer.from(ecpair.publicKey.slice(1, 33)),
      undefined
    );
    const tweakedEcpair = ecpair.tweak(hash);
    psbt.signInput(index, tweakedEcpair);
  } else psbt.signInput(index, ecpair);
}
export function signECPair({
  psbt,
  ecpair
}: {
  psbt: Psbt;
  ecpair: ECPairInterface;
}): void {
  //psbt.signAllInputs(ecpair); <- replaced for the code below that handles
  //taptoot automatically.
  //See https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
  const results: boolean[] = [];
  for (const index of range(psbt.data.inputs.length)) {
    try {
      signInputECPair({ psbt, index, ecpair });
      results.push(true);
    } catch (err) {
      results.push(false);
    }
  }
  if (results.every(v => v === false)) {
    throw new Error('No inputs were signed');
  }
}
export function signInputBIP32({
  psbt,
  index,
  node
}: {
  psbt: Psbt;
  index: number;
  node: BIP32Interface;
}): void {
  applyPR2137(psbt);
  psbt.signInputHD(index, node);
}

export function signBIP32({
  psbt,
  masterNode
}: {
  psbt: Psbt;
  masterNode: BIP32Interface;
}): void {
  applyPR2137(psbt);
  psbt.signAllInputsHD(masterNode);
}

const ledgerSignaturesForInputIndex = (
  index: number,
  ledgerSignatures: [number, PartialSignature][]
) =>
  ledgerSignatures
    .filter(([i]: [number, PartialSignature]) => i === index)
    .map(([_i, partialSignature]: [number, PartialSignature]) => ({
      pubkey: partialSignature.pubkey,
      signature: partialSignature.signature
    }));

/**
 * Signs an input of the `psbt` where the keys are controlled by a Ledger
 * device.
 *
 * The function will throw an error if it's unable to sign the input.
 */
export async function signInputLedger({
  psbt,
  index,
  ledgerManager
}: {
  psbt: Psbt;
  index: number;
  ledgerManager: LedgerManager;
}): Promise<void>;

/**
 * @deprecated
 * @hidden
 */
export async function signInputLedger({
  psbt,
  index,
  descriptor,
  ledgerClient,
  ledgerState
}: {
  psbt: Psbt;
  index: number;
  descriptor: DescriptorInstance;
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<void>;

/**
 * To be removed in v3.0 and replaced by a version that does not accept
 * descriptor
 * @hidden
 */
export async function signInputLedger({
  psbt,
  index,
  descriptor,
  ledgerClient,
  ledgerState,
  ledgerManager
}: {
  psbt: Psbt;
  index: number;
  descriptor?: DescriptorInstance;
  ledgerClient?: unknown;
  ledgerState?: LedgerState;
  ledgerManager?: LedgerManager;
}): Promise<void> {
  if (!descriptor && !ledgerManager)
    throw new Error(`ledgerManager not provided`);
  if (descriptor && ledgerManager)
    throw new Error(`Invalid usage: don't pass descriptor`);
  if (ledgerManager && (ledgerClient || ledgerState))
    throw new Error(
      `Invalid usage: either ledgerManager or ledgerClient + ledgerState`
    );
  const output = descriptor;
  if (ledgerManager) ({ ledgerClient, ledgerState } = ledgerManager);
  if (!ledgerClient) throw new Error(`ledgerManager not provided`);
  if (!ledgerState) throw new Error(`ledgerManager not provided`);
  const { PsbtV2, DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  let ledgerSignatures;
  if (ledgerManager) {
    if (psbt.data.inputs[index]?.tapInternalKey)
      throw new Error('Taproot inputs not yet supported for the Ledger device');
    const policy = await ledgerPolicyFromPsbtInput({
      psbt,
      index,
      ledgerManager
    });
    if (!policy)
      throw new Error(`Error: the ledger cannot sign this pstb input`);
    if (policy.policyName && policy.policyHmac && policy.policyId) {
      //non-standard policy
      const walletPolicy = new WalletPolicy(
        policy.policyName,
        policy.ledgerTemplate,
        policy.keyRoots
      );

      ledgerSignatures = await ledgerClient.signPsbt(
        new PsbtV2().fromBitcoinJS(psbt),
        walletPolicy,
        policy.policyHmac
      );
    } else {
      //standard policy
      ledgerSignatures = await ledgerClient.signPsbt(
        new PsbtV2().fromBitcoinJS(psbt),
        new DefaultWalletPolicy(
          policy.ledgerTemplate as DefaultDescriptorTemplate,
          policy.keyRoots[0]!
        ),
        null
      );
    }
  } else {
    if (!output) throw new Error(`outputs not provided`);
    const result = await ledgerPolicyFromOutput({
      output,
      ledgerClient,
      ledgerState
    });
    if (!result) throw new Error(`Error: output does not have a ledger input`);
    const { ledgerTemplate, keyRoots } = result;

    const standardPolicy = await ledgerPolicyFromStandard({
      output,
      ledgerClient,
      ledgerState
    });
    if (standardPolicy) {
      ledgerSignatures = await ledgerClient.signPsbt(
        new PsbtV2().fromBitcoinJS(psbt),
        new DefaultWalletPolicy(
          ledgerTemplate as DefaultDescriptorTemplate,
          keyRoots[0]!
        ),
        null
      );
    } else {
      const policy = await ledgerPolicyFromState({
        output,
        ledgerClient,
        ledgerState
      });
      if (!policy || !policy.policyName || !policy.policyHmac)
        throw new Error(`Error: the descriptor's policy is not registered`);
      const walletPolicy = new WalletPolicy(
        policy.policyName,
        ledgerTemplate,
        keyRoots
      );

      ledgerSignatures = await ledgerClient.signPsbt(
        new PsbtV2().fromBitcoinJS(psbt),
        walletPolicy,
        policy.policyHmac
      );
    }
  }

  //Add the signatures to the Psbt object using PartialSig format:
  psbt.updateInput(index, {
    partialSig: ledgerSignaturesForInputIndex(index, ledgerSignatures)
  });
}

/**
 * Signs the inputs of the `psbt` where the keys are controlled by a Ledger
 * device.
 *
 * `signLedger` can sign multiple inputs of the same wallet policy in a single
 * pass by grouping inputs by their wallet policy type before the signing
 * process.
 *
 * The function will throw an error if it's unable to sign any input.
 */
export async function signLedger({
  psbt,
  ledgerManager
}: {
  psbt: Psbt;
  ledgerManager: LedgerManager;
}): Promise<void>;

/**
 * @deprecated
 * @hidden
 */
export async function signLedger({
  psbt,
  descriptors,
  ledgerClient,
  ledgerState
}: {
  psbt: Psbt;
  descriptors: DescriptorInstance[];
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<void>;

/**
 * To be removed in v3.0 and replaced by a version that does not accept
 * descriptors
 * @hidden
 */
export async function signLedger({
  psbt,
  descriptors,
  ledgerClient,
  ledgerState,
  ledgerManager
}: {
  psbt: Psbt;
  descriptors?: DescriptorInstance[];
  ledgerClient?: unknown;
  ledgerState?: LedgerState;
  ledgerManager?: LedgerManager;
}): Promise<void> {
  if (!descriptors && !ledgerManager)
    throw new Error(`ledgerManager not provided`);
  if (descriptors && ledgerManager)
    throw new Error(`Invalid usage: don't pass descriptors`);
  if (ledgerManager && (ledgerClient || ledgerState))
    throw new Error(
      `Invalid usage: either ledgerManager or ledgerClient + ledgerState`
    );
  const outputs = descriptors;
  if (ledgerManager) ({ ledgerClient, ledgerState } = ledgerManager);
  if (!ledgerClient) throw new Error(`ledgerManager not provided`);
  if (!ledgerState) throw new Error(`ledgerManager not provided`);
  const { PsbtV2, DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  const ledgerPolicies = [];
  if (ledgerManager)
    for (let index = 0; index < psbt.data.inputs.length; index++) {
      if (psbt.data.inputs[index]?.tapInternalKey)
        throw new Error(
          'Taproot inputs not yet supported for the Ledger device'
        );
      const policy = await ledgerPolicyFromPsbtInput({
        psbt,
        index,
        ledgerManager
      });
      if (policy) ledgerPolicies.push(policy);
    }
  else {
    if (!outputs) throw new Error(`outputs not provided`);
    for (const output of outputs) {
      const policy =
        (await ledgerPolicyFromState({ output, ledgerClient, ledgerState })) ||
        (await ledgerPolicyFromStandard({ output, ledgerClient, ledgerState }));
      if (policy) ledgerPolicies.push(policy);
    }
    if (ledgerPolicies.length === 0)
      throw new Error(`Error: there are no inputs which could be signed`);
  }
  //cluster unique LedgerPolicies
  const uniquePolicies: LedgerPolicy[] = [];
  for (const policy of ledgerPolicies) {
    if (
      !uniquePolicies.find((uniquePolicy: LedgerPolicy) =>
        comparePolicies(uniquePolicy, policy)
      )
    )
      uniquePolicies.push(policy);
  }

  for (const uniquePolicy of uniquePolicies) {
    let ledgerSignatures;
    if (
      uniquePolicy.policyName &&
      uniquePolicy.policyHmac &&
      uniquePolicy.policyId
    ) {
      //non-standard policy
      const walletPolicy = new WalletPolicy(
        uniquePolicy.policyName,
        uniquePolicy.ledgerTemplate,
        uniquePolicy.keyRoots
      );

      ledgerSignatures = await ledgerClient.signPsbt(
        new PsbtV2().fromBitcoinJS(psbt),
        walletPolicy,
        uniquePolicy.policyHmac
      );
    } else {
      //standard policy
      ledgerSignatures = await ledgerClient.signPsbt(
        new PsbtV2().fromBitcoinJS(psbt),
        new DefaultWalletPolicy(
          uniquePolicy.ledgerTemplate as DefaultDescriptorTemplate,
          uniquePolicy.keyRoots[0]!
        ),
        null
      );
    }

    for (const [index, ,] of ledgerSignatures) {
      psbt.updateInput(index, {
        partialSig: ledgerSignaturesForInputIndex(index, ledgerSignatures)
      });
    }
  }
}
