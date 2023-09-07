// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { Psbt } from 'bitcoinjs-lib';
import type { ECPairInterface } from 'ecpair';
import type { BIP32Interface } from 'bip32';
import type { Descriptor } from './descriptors';
import {
  importAndValidateLedgerBitcoin,
  comparePolicies,
  LedgerPolicy,
  ledgerPolicyFromState,
  ledgerPolicyFromStandard,
  descriptorToLedgerFormat,
  LedgerState
} from './ledger';
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
export function signInputECPair({
  psbt,
  index,
  ecpair
}: {
  psbt: Psbt;
  index: number;
  ecpair: ECPairInterface;
}): void {
  psbt.signInput(index, ecpair);
}
export function signECPair({
  psbt,
  ecpair
}: {
  psbt: Psbt;
  ecpair: ECPairInterface;
}): void {
  psbt.signAllInputs(ecpair);
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
  psbt.signInputHD(index, node);
}
export function signBIP32({
  psbt,
  masterNode
}: {
  psbt: Psbt;
  masterNode: BIP32Interface;
}): void {
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

export async function signInputLedger({
  psbt,
  index,
  descriptor,
  ledgerClient,
  ledgerState
}: {
  psbt: Psbt;
  index: number;
  descriptor: Descriptor;
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<void> {
  const { PsbtV2, DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  const result = await descriptorToLedgerFormat({
    descriptor,
    ledgerClient,
    ledgerState
  });
  if (!result)
    throw new Error(`Error: descriptor does not have a ledger input`);
  const { ledgerTemplate, keyRoots } = result;

  let ledgerSignatures;
  const standardPolicy = await ledgerPolicyFromStandard({
    descriptor,
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
      descriptor,
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

  //Add the signatures to the Psbt object using PartialSig format:
  psbt.updateInput(index, {
    partialSig: ledgerSignaturesForInputIndex(index, ledgerSignatures)
  });
}

//signLedger is able to sign several inputs of the same wallet policy since it
//it clusters together wallet policy types before signing
//it throws if it cannot sign any input.
export async function signLedger({
  psbt,
  descriptors,
  ledgerClient,
  ledgerState
}: {
  psbt: Psbt;
  descriptors: Descriptor[];
  ledgerClient: unknown;
  ledgerState: LedgerState;
}): Promise<void> {
  const { PsbtV2, DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);
  const ledgerPolicies = [];
  for (const descriptor of descriptors) {
    const policy =
      (await ledgerPolicyFromState({
        descriptor,
        ledgerClient,
        ledgerState
      })) ||
      (await ledgerPolicyFromStandard({
        descriptor,
        ledgerClient,
        ledgerState
      }));
    if (policy) ledgerPolicies.push(policy);
  }
  if (ledgerPolicies.length === 0)
    throw new Error(`Error: there are no inputs which could be signed`);

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
