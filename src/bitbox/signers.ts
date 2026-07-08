// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import { toPsbt } from '../psbt';
import { policyForPsbtInput } from '../hww/policies';
import { formatUnit, apiNetwork } from './client';
import {
  assertPolicyCanDerive,
  signingKeypathFromPolicy,
  scriptConfigFromPolicy
} from './scriptConfig';
import { policyResolverFromSession } from './policyResolver';
import type { BitBoxScriptConfigWithKeypath, BitBoxSession } from './types';

type MergeablePsbt = PsbtLike & {
  combine(...psbts: PsbtLike[]): unknown;
  constructor: { fromBase64?(psbt: string): PsbtLike };
};

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
  const policyResolver = policyResolverFromSession(session);

  for (let index = 0; index < psbt.data.inputs.length; index++) {
    const policy = await policyForPsbtInput({
      psbt,
      index,
      policyResolver
    });
    if (!policy) continue;

    assertPolicyCanDerive(policy);
    const scriptConfig = scriptConfigFromPolicy({
      policy,
      session
    });
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

function mergeSignedPsbtIfPossible({
  psbt,
  signedPsbt
}: {
  psbt: PsbtLike;
  signedPsbt: string;
}) {
  const maybeMergeable = psbt as Partial<MergeablePsbt>;
  const PsbtConstructor = maybeMergeable.constructor;
  if (
    typeof maybeMergeable.combine !== 'function' ||
    typeof PsbtConstructor?.fromBase64 !== 'function'
  )
    return;
  maybeMergeable.combine(PsbtConstructor.fromBase64(signedPsbt));
}

export async function sign({
  psbt,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  session: BitBoxSession;
}): Promise<string> {
  psbt = toPsbt(psbt);
  const forcedScriptConfig = await forcedScriptConfigForPsbt({ psbt, session });
  const signedPsbt = await session.client.btcSignPSBT(
    apiNetwork(session),
    psbt.toBase64(),
    forcedScriptConfig,
    formatUnit(session)
  );
  mergeSignedPsbtIfPossible({ psbt, signedPsbt });
  return signedPsbt;
}

export async function signInput({
  psbt,
  index,
  session
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  session: BitBoxSession;
}): Promise<string> {
  psbt = toPsbt(psbt);
  if (!psbt.data.inputs[index])
    throw new Error(`Error: input ${index} not available`);
  if (psbt.data.inputs.length !== 1 || index !== 0)
    throw new Error(
      `BitBox btcSignPSBT signs a whole PSBT; signInput is only supported for single-input PSBTs`
    );
  return sign({ psbt, session });
}
