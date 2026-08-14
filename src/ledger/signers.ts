// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { type ScureTransactionLike, type PsbtLike } from '../bitcoinLib';
// Used only to forward deprecated LedgerManager.Output. Remove in v4.
import type { OutputConstructor } from '../descriptors';
import { toPsbt } from '../psbt';
import { isTaprootInput } from '../bitcoinjs-lib-internals';
import {
  isStandardPolicy,
  policyForPsbtInput,
  samePolicy
} from '../hww/policies';
import {
  getMasterFingerprint,
  getXpub,
  sessionFromLedgerManager
} from './client';
import { fromHex } from 'uint8array-tools';
import type {
  LedgerManager,
  LedgerDefaultDescriptorTemplate,
  LedgerPolicy,
  LedgerPartialSignature,
  LedgerSession
} from './types';

type PartialSignature = LedgerPartialSignature;

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

export async function signInput({
  psbt,
  index,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  session: LedgerSession;
}): Promise<void> {
  return signInputWithLegacyOutput({ psbt, index, session });
}

/**
 * Threads the released `LedgerManager.Output` override into input matching.
 * Inline this body into `signInput(...)` and remove the override in v4.
 *
 * @deprecated 3.x LedgerManager compatibility only.
 * @internal
 */
async function signInputWithLegacyOutput({
  psbt,
  index,
  session,
  legacyOutput
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  session: LedgerSession;
  /** @deprecated 3.x LedgerManager compatibility only. Remove in v4. */
  legacyOutput?: OutputConstructor;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const { client } = session;
  const { DefaultWalletPolicy, WalletPolicy } = session.bitcoinApi;

  const policy = (await policyForPsbtInput({
    psbt,
    index,
    network: session.network,
    getMasterFingerprint: () => getMasterFingerprint({ session }),
    getAccountXpub: originPath => getXpub({ originPath, session }),
    ...(session.store.policies !== undefined
      ? { knownPolicies: session.store.policies }
      : {}),
    ...(legacyOutput !== undefined ? { legacyOutput } : {})
  })) as LedgerPolicy | undefined;
  if (!policy) throw new Error(`Error: the Ledger cannot sign this PSBT input`);

  let ledgerSignatures;
  if (policy.name && policy.policyHmac) {
    const walletPolicy = new WalletPolicy(
      policy.name,
      policy.descriptorTemplate,
      policy.keyRoots
    );

    const walletHmac = fromHex(policy.policyHmac) as unknown as Parameters<
      typeof client.signPsbt
    >[2];
    ledgerSignatures = await client.signPsbt(
      psbt.toBase64(),
      walletPolicy,
      walletHmac
    );
  } else if (
    isStandardPolicy({
      descriptorTemplate: policy.descriptorTemplate,
      keyRoots: policy.keyRoots,
      network: session.network
    })
  )
    ledgerSignatures = await client.signPsbt(
      psbt.toBase64(),
      new DefaultWalletPolicy(
        policy.descriptorTemplate as LedgerDefaultDescriptorTemplate,
        policy.keyRoots[0]!
      ),
      null
    );
  else
    throw new Error(
      `Stored Ledger policy registration is incomplete; call registerPolicy again`
    );

  addLedgerSignaturesToInput({ psbt, index, ledgerSignatures });
}

/**
 * @deprecated Use `signInput(...)` instead. Remove in v4 with `LedgerManager`
 * compatibility.
 */
export async function signInputLedger({
  psbt,
  index,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  ledgerManager: LedgerManager;
}): Promise<void> {
  return signInputWithLegacyOutput({
    psbt,
    index,
    session: sessionFromLedgerManager(ledgerManager),
    ...(ledgerManager.Output !== undefined
      ? { legacyOutput: ledgerManager.Output }
      : {})
  });
}

export async function sign({
  psbt,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  session: LedgerSession;
}): Promise<void> {
  return signWithLegacyOutput({ psbt, session });
}

/**
 * Threads the released `LedgerManager.Output` override into input matching.
 * Inline this body into `sign(...)` and remove the override in v4.
 *
 * @deprecated 3.x LedgerManager compatibility only.
 * @internal
 */
async function signWithLegacyOutput({
  psbt,
  session,
  legacyOutput
}: {
  psbt: PsbtLike | ScureTransactionLike;
  session: LedgerSession;
  /** @deprecated 3.x LedgerManager compatibility only. Remove in v4. */
  legacyOutput?: OutputConstructor;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const { client } = session;
  const { DefaultWalletPolicy, WalletPolicy } = session.bitcoinApi;

  const ledgerPolicies = [];
  for (let index = 0; index < psbt.data.inputs.length; index++) {
    const policy = (await policyForPsbtInput({
      psbt,
      index,
      network: session.network,
      getMasterFingerprint: () => getMasterFingerprint({ session }),
      getAccountXpub: originPath => getXpub({ originPath, session }),
      ...(session.store.policies !== undefined
        ? { knownPolicies: session.store.policies }
        : {}),
      ...(legacyOutput !== undefined ? { legacyOutput } : {})
    })) as LedgerPolicy | undefined;
    if (policy) ledgerPolicies.push(policy);
  }
  if (ledgerPolicies.length === 0)
    throw new Error(`Error: there are no inputs which could be signed`);

  const uniquePolicies: LedgerPolicy[] = [];
  for (const policy of ledgerPolicies) {
    if (
      !uniquePolicies.find((uniquePolicy: LedgerPolicy) =>
        samePolicy(uniquePolicy, policy)
      )
    )
      uniquePolicies.push(policy);
  }

  for (const uniquePolicy of uniquePolicies) {
    let ledgerSignatures;
    if (uniquePolicy.name && uniquePolicy.policyHmac) {
      const walletPolicy = new WalletPolicy(
        uniquePolicy.name,
        uniquePolicy.descriptorTemplate,
        uniquePolicy.keyRoots
      );

      const walletHmac = fromHex(
        uniquePolicy.policyHmac
      ) as unknown as Parameters<typeof client.signPsbt>[2];
      ledgerSignatures = await client.signPsbt(
        psbt.toBase64(),
        walletPolicy,
        walletHmac
      );
    } else if (
      isStandardPolicy({
        descriptorTemplate: uniquePolicy.descriptorTemplate,
        keyRoots: uniquePolicy.keyRoots,
        network: session.network
      })
    )
      ledgerSignatures = await client.signPsbt(
        psbt.toBase64(),
        new DefaultWalletPolicy(
          uniquePolicy.descriptorTemplate as LedgerDefaultDescriptorTemplate,
          uniquePolicy.keyRoots[0]!
        ),
        null
      );
    else
      throw new Error(
        `Stored Ledger policy registration is incomplete; call registerPolicy again`
      );

    const signedIndexes = [
      ...new Set(ledgerSignatures.map(([index]) => index))
    ];
    for (const index of signedIndexes) {
      addLedgerSignaturesToInput({ psbt, index, ledgerSignatures });
    }
  }
}

/**
 * @deprecated Use `sign(...)` instead. Remove in v4 with `LedgerManager`
 * compatibility.
 */
export async function signLedger({
  psbt,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  ledgerManager: LedgerManager;
}): Promise<void> {
  return signWithLegacyOutput({
    psbt,
    session: sessionFromLedgerManager(ledgerManager),
    ...(ledgerManager.Output !== undefined
      ? { legacyOutput: ledgerManager.Output }
      : {})
  });
}
