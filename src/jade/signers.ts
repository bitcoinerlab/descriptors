// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { compare, fromBase64, toBase64 } from 'uint8array-tools';
import {
  getBitcoinLibOrThrow,
  type PsbtLike,
  type ScureTransactionLike
} from '../bitcoinLib';
import { isStandardPolicy, policyForPsbtInput } from '../hww/policies';
import { toPsbt } from '../psbt';
import { getMasterFingerprint, getXpub, jadeNetwork } from './client';
import {
  assertDevicePolicyMatches,
  assertJadePolicySupported
} from './policies';
import type { JadeSession } from './types';

/** Signs every input owned by Jade and merges the returned PSBT. */
export async function sign({
  psbt,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  session: JadeSession;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const masterFingerprint = await getMasterFingerprint({ session });
  let ownedInputs = 0;
  const checkedPolicies = new Set<string>();

  for (let index = 0; index < psbt.data.inputs.length; index++) {
    const input = psbt.data.inputs[index]!;
    const bip32Derivations = input.bip32Derivation ?? [];
    const taprootDerivations = input.tapBip32Derivation ?? [];
    const ownsInput = [...bip32Derivations, ...taprootDerivations].some(
      derivation =>
        compare(derivation.masterFingerprint, masterFingerprint) === 0
    );
    if (!ownsInput) continue;
    ownedInputs += 1;

    const ownsTaprootKey = taprootDerivations.some(
      derivation =>
        compare(derivation.masterFingerprint, masterFingerprint) === 0
    );
    if (
      ownsTaprootKey &&
      (input.tapMerkleRoot !== undefined ||
        (input.tapLeafScript?.length ?? 0) > 0 ||
        taprootDerivations.some(
          derivation =>
            compare(derivation.masterFingerprint, masterFingerprint) === 0 &&
            derivation.leafHashes.length > 0
        ))
    )
      throw new Error(
        `Jade cannot sign input ${index}: Taproot trees and script-path spending are not supported`
      );

    const policy = await policyForPsbtInput({
      psbt,
      index,
      network: session.network,
      getMasterFingerprint: () => getMasterFingerprint({ session }),
      getAccountXpub: originPath => getXpub({ originPath, session }),
      ...(session.store.policies !== undefined
        ? { knownPolicies: session.store.policies }
        : {})
    });
    if (!policy)
      throw new Error(
        `Jade cannot sign input ${index}: policy not registered; call registerPolicy first`
      );
    assertJadePolicySupported(policy);
    const isStandard = isStandardPolicy({
      descriptorTemplate: policy.descriptorTemplate,
      keyRoots: policy.keyRoots,
      network: session.network
    });
    if (!isStandard && !policy.name)
      throw new Error(
        `Jade cannot sign input ${index}: policy registration is incomplete; call registerPolicy again`
      );
    if (!isStandard && !checkedPolicies.has(policy.name!)) {
      await assertDevicePolicyMatches({ policy, session });
      checkedPolicies.add(policy.name!);
    }
  }

  if (ownedInputs === 0)
    throw new Error(`Error: there are no inputs which could be signed`);

  const signedPsbt = await session.client.signPSBT(
    jadeNetwork(session.network),
    fromBase64(psbt.toBase64())
  );
  if (!(signedPsbt instanceof Uint8Array) || signedPsbt.length === 0)
    throw new Error(`Jade client returned an invalid PSBT`);
  getBitcoinLibOrThrow().mergePsbt(psbt, toBase64(signedPsbt));
}
