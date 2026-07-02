// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import type { PsbtLike, ScureTransactionLike } from '../bitcoinLib';
import { toPsbt } from '../psbt';
import { bitboxFormatUnit, bitboxCoin } from './client';
import {
  bitboxPolicyFromPsbtInput,
  bitboxSigningKeypathFromPolicy,
  bitboxScriptConfigFromPolicy
} from './policies';
import type {
  BitBoxManager,
  BitBoxPolicy,
  BitBoxScriptConfigWithKeypath
} from './types';

type MergeablePsbt = PsbtLike & {
  combine(...psbts: PsbtLike[]): unknown;
  constructor: { fromBase64?(psbt: string): PsbtLike };
};

function samePolicy(left: BitBoxPolicy, right: BitBoxPolicy): boolean {
  return (
    left.descriptorTemplate === right.descriptorTemplate &&
    left.keyRoots.length === right.keyRoots.length &&
    left.keyRoots.every((keyRoot, index) => keyRoot === right.keyRoots[index])
  );
}

function policyWithCachedAccount({
  policy,
  manager
}: {
  policy: BitBoxPolicy;
  manager: BitBoxManager;
}): BitBoxPolicy {
  return (
    manager.bitboxState.policies?.find(cachedPolicy =>
      samePolicy(cachedPolicy, policy)
    ) ?? policy
  );
}

async function forcedScriptConfigForPsbt({
  psbt,
  manager
}: {
  psbt: PsbtLike;
  manager: BitBoxManager;
}): Promise<BitBoxScriptConfigWithKeypath | undefined> {
  const configs = new Map<string, BitBoxScriptConfigWithKeypath>();

  for (let index = 0; index < psbt.data.inputs.length; index++) {
    const policy = await bitboxPolicyFromPsbtInput({
      psbt,
      index,
      bitboxManager: manager
    });
    if (!policy) continue;

    const policyWithAccount = policyWithCachedAccount({ policy, manager });
    const scriptConfig = bitboxScriptConfigFromPolicy({
      policy: policyWithAccount,
      bitboxManager: manager
    });
    if (!('multisig' in scriptConfig) && !('policy' in scriptConfig)) continue;

    const keypath =
      'multisig' in scriptConfig
        ? policyWithAccount.account?.keypathAccount
        : bitboxSigningKeypathFromPolicy({
            policy: policyWithAccount,
            bitboxManager: manager
          });
    if (!keypath)
      throw new Error(
        `BitBox policy missing account; call registerBitBoxWallet first`
      );
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
  const fromBase64 = maybeMergeable.constructor?.fromBase64;
  if (typeof maybeMergeable.combine !== 'function' || !fromBase64) return;
  maybeMergeable.combine(fromBase64(signedPsbt));
}

export async function sign({
  psbt,
  manager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  manager: BitBoxManager;
}): Promise<string> {
  psbt = toPsbt(psbt);
  const forcedScriptConfig = await forcedScriptConfigForPsbt({ psbt, manager });
  const signedPsbt = await manager.bitboxClient.btcSignPSBT(
    bitboxCoin(manager),
    psbt.toBase64(),
    forcedScriptConfig,
    bitboxFormatUnit(manager)
  );
  mergeSignedPsbtIfPossible({ psbt, signedPsbt });
  return signedPsbt;
}

export async function signInput({
  psbt,
  index,
  manager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  manager: BitBoxManager;
}): Promise<string> {
  psbt = toPsbt(psbt);
  if (!psbt.data.inputs[index])
    throw new Error(`Error: input ${index} not available`);
  if (psbt.data.inputs.length !== 1 || index !== 0)
    throw new Error(
      `BitBox btcSignPSBT signs a whole PSBT; signInput is only supported for single-input PSBTs`
    );
  return sign({ psbt, manager });
}
