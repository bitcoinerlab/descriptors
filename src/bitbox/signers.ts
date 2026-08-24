// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  getBitcoinLibOrThrow,
  type PsbtLike,
  type ScureTransactionLike
} from '../bitcoinLib';
import { toPsbt } from '../psbt';
import { policyForPsbtInput } from '../hww/policies';
import { apiNetwork, getMasterFingerprint, getXpub } from './client';
import {
  assertPolicyCanDerive,
  signingKeypathFromPolicy,
  scriptConfigFromPolicy
} from './scriptConfig';
import type { BitBoxScriptConfigWithKeypath, BitBoxSession } from './types';

/**
 * Finds the explicit BitBox script config needed to sign this PSBT.
 *
 * The name matches BitBox's `forceScriptConfig` signing parameter. "Forced"
 * means we pass the config to the device instead of letting the device infer it.
 * Standard single-key inputs return `undefined` because BitBox can infer them.
 * Registered multisig and policy inputs return `{ scriptConfig, keypath }`.
 *
 * Examples:
 * - `wpkh(...)` returns `undefined`.
 * - `wsh(sortedmulti(...))` returns the native multisig config and account path.
 * - Generic Miniscript policies return the policy config and account path.
 *
 * BitBox accepts only one forced script config per PSBT, so mixed policy inputs
 * with different configs are rejected before calling the device.
 */
async function forcedScriptConfigForPsbt({
  psbt,
  session
}: {
  psbt: PsbtLike;
  session: BitBoxSession;
}): Promise<BitBoxScriptConfigWithKeypath | undefined> {
  const configs = new Map<string, BitBoxScriptConfigWithKeypath>();

  for (let index = 0; index < psbt.data.inputs.length; index++) {
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
        `BitBox cannot sign input ${index}: every PSBT input must include a key owned by the connected BitBox`
      );

    assertPolicyCanDerive(policy);
    const scriptConfig = scriptConfigFromPolicy({ policy, session });
    if (!('multisig' in scriptConfig) && !('policy' in scriptConfig)) continue;

    const keypath = signingKeypathFromPolicy({ policy, session });
    const forcedScriptConfig = { scriptConfig, keypath };
    configs.set(JSON.stringify(forcedScriptConfig), forcedScriptConfig);
  }

  if (configs.size > 1)
    throw new Error(
      `BitBox btcSignPSBT accepts only one forced script config per PSBT`
    );
  return [...configs.values()][0];
}

/**
 * Signs a complete PSBT and merges the signatures into the supplied object.
 *
 * BitBox does not expose per-input signing. Its API signs the complete PSBT, so
 * this module intentionally does not provide `signInput(...)`. Every input in
 * the PSBT must include a key owned by the connected BitBox.
 */
export async function sign({
  psbt,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  session: BitBoxSession;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const forcedScriptConfig = await forcedScriptConfigForPsbt({ psbt, session });
  const signedPsbt = await session.client.btcSignPSBT(
    apiNetwork(session),
    psbt.toBase64(),
    forcedScriptConfig,
    session.formatUnit ?? 'default'
  );
  getBitcoinLibOrThrow().mergePsbt(psbt, signedPsbt);
}
