// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { type ScureTransactionLike, type PsbtLike } from '../bitcoinLib';
import { toPsbt } from '../psbt';
import { isTaprootInput } from '../bitcoinjs-lib-internals';
import { importAndValidateLedgerBitcoin } from './client';
import {
  comparePolicies,
  type LedgerPolicy,
  ledgerPolicyFromPsbtInput
} from './policies';
import type { LedgerManager } from './index';

type DefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';

declare class PartialSignature {
  readonly pubkey: Uint8Array;
  readonly signature: Uint8Array;
  readonly tapleafHash?: Uint8Array;
  constructor(
    pubkey: Uint8Array,
    signature: Uint8Array,
    tapleafHash?: Uint8Array
  );
}

const ledgerSignaturesForInputIndex = (
  index: number,
  ledgerSignatures: [number, PartialSignature][]
) =>
  ledgerSignatures
    .filter(([i]: [number, PartialSignature]) => i === index)
    .map(
      ([_i, partialSignature]: [number, PartialSignature]) => partialSignature
    );

function addLedgerSignaturesToInput({
  psbt,
  index,
  ledgerSignatures
}: {
  psbt: PsbtLike;
  index: number;
  ledgerSignatures: [number, PartialSignature][];
}) {
  const input = psbt.data.inputs[index];
  if (!input) throw new Error(`Error: input ${index} not available`);

  const signatures = ledgerSignaturesForInputIndex(index, ledgerSignatures);
  if (signatures.length === 0)
    throw new Error(`Error: no ledger signatures found for input ${index}`);

  if (isTaprootInput(input)) {
    const tapScriptSig = signatures
      .filter((sig: PartialSignature) => sig.tapleafHash)
      .map((sig: PartialSignature) => ({
        pubkey: sig.pubkey,
        signature: sig.signature,
        leafHash: sig.tapleafHash!
      }));
    const tapKeySigs = signatures.filter(
      (sig: PartialSignature) => !sig.tapleafHash
    );

    if (tapScriptSig.length > 0) {
      psbt.updateInput(index, { tapScriptSig });
    }

    if (tapKeySigs.length > 1)
      throw new Error(
        `Error: expected at most one tapKeySig for input ${index}`
      );
    const tapKeySig = tapKeySigs[0]?.signature;
    if (tapKeySig) {
      psbt.updateInput(index, { tapKeySig });
    }

    if (tapScriptSig.length === 0 && !tapKeySig)
      throw new Error(
        `Error: no valid taproot ledger signatures found for input ${index}`
      );
  } else {
    const partialSig = signatures.map((sig: PartialSignature) => ({
      pubkey: sig.pubkey,
      signature: sig.signature
    }));
    psbt.updateInput(index, { partialSig });
  }
}

export async function signInputLedger({
  psbt,
  index,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  ledgerManager: LedgerManager;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const { ledgerClient } = ledgerManager;
  const { DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  const policy = await ledgerPolicyFromPsbtInput({
    psbt,
    index,
    ledgerManager
  });
  if (!policy) throw new Error(`Error: the ledger cannot sign this pstb input`);

  let ledgerSignatures;
  if (policy.policyName && policy.policyHmac && policy.policyId) {
    const walletPolicy = new WalletPolicy(
      policy.policyName,
      policy.ledgerTemplate,
      policy.keyRoots
    );

    const walletHmac = policy.policyHmac as unknown as Parameters<
      typeof ledgerClient.signPsbt
    >[2];
    ledgerSignatures = await ledgerClient.signPsbt(
      psbt.toBase64(),
      walletPolicy,
      walletHmac
    );
  } else {
    ledgerSignatures = await ledgerClient.signPsbt(
      psbt.toBase64(),
      new DefaultWalletPolicy(
        policy.ledgerTemplate as DefaultDescriptorTemplate,
        policy.keyRoots[0]!
      ),
      null
    );
  }

  addLedgerSignaturesToInput({ psbt, index, ledgerSignatures });
}

export async function signLedger({
  psbt,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  ledgerManager: LedgerManager;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const { ledgerClient } = ledgerManager;
  const { DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  const ledgerPolicies = [];
  for (let index = 0; index < psbt.data.inputs.length; index++) {
    const policy = await ledgerPolicyFromPsbtInput({
      psbt,
      index,
      ledgerManager
    });
    if (policy) ledgerPolicies.push(policy);
  }
  if (ledgerPolicies.length === 0)
    throw new Error(`Error: there are no inputs which could be signed`);

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
      const walletPolicy = new WalletPolicy(
        uniquePolicy.policyName,
        uniquePolicy.ledgerTemplate,
        uniquePolicy.keyRoots
      );

      const walletHmac = uniquePolicy.policyHmac as unknown as Parameters<
        typeof ledgerClient.signPsbt
      >[2];
      ledgerSignatures = await ledgerClient.signPsbt(
        psbt.toBase64(),
        walletPolicy,
        walletHmac
      );
    } else {
      ledgerSignatures = await ledgerClient.signPsbt(
        psbt.toBase64(),
        new DefaultWalletPolicy(
          uniquePolicy.ledgerTemplate as DefaultDescriptorTemplate,
          uniquePolicy.keyRoots[0]!
        ),
        null
      );
    }

    const signedIndexes = [
      ...new Set(ledgerSignatures.map(([index]) => index))
    ];
    for (const index of signedIndexes) {
      addLedgerSignaturesToInput({ psbt, index, ledgerSignatures });
    }
  }
}
