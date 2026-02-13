// Copyright (c) 2026 Jose-Luis Landabaso
// Distributed under the MIT software license

import { payments, script as bscript } from 'bitcoinjs-lib';
import type { Network } from 'bitcoinjs-lib';

const { p2sh } = payments;

// See Sipa's Miniscript "Resource limitations":
// https://bitcoin.sipa.be/miniscript/
// and Bitcoin Core policy/consensus constants.
//https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.h

// Consensus: max number of elements in initial stack (and stack+altstack after
// each opcode execution).
const MAX_STACK_SIZE = 1000;

// Consensus: max size for any stack element is 520 bytes.
// This is a per-element limit, not a full script-size limit.
// In legacy P2SH, redeemScript is pushed as a stack element,
// ( this is why we typically say that the redeemScript cannot be larger than 520 ).
// But the same per-element rule applies to other stack items as well.
export const MAX_SCRIPT_ELEMENT_SIZE = 520;

// Standardness policy limits.
// See Sipa's Miniscript "Resource limitations":
// https://bitcoin.sipa.be/miniscript/
// and Bitcoin Core policy/consensus constants.
//https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.h
export const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
const MAX_STANDARD_P2WSH_STACK_ITEMS = 100;
const MAX_OPS_PER_SCRIPT = 201;
const MAX_STANDARD_SCRIPTSIG_SIZE = 1650;
const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80;
const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80;

function countNonPushOnlyOPs(script: Uint8Array): number {
  const chunks = bscript.decompile(script);
  if (!chunks) throw new Error(`Error: could not decompile ${script}`);
  return bscript.countNonPushOnlyOPs(chunks);
}

export function assertScriptNonPushOnlyOpsLimit({
  script
}: {
  script: Uint8Array;
}): void {
  const nonPushOnlyOps = countNonPushOnlyOPs(script);
  if (nonPushOnlyOps > MAX_OPS_PER_SCRIPT)
    throw new Error(
      `Error: too many non-push ops, ${nonPushOnlyOps} non-push ops is larger than ${MAX_OPS_PER_SCRIPT}`
    );
}

/**
 * Enforces consensus stack resource limits.
 */
export function assertConsensusStackResourceLimits({
  stackItems,
  stackLabel = 'stack',
  stackItemLabel = 'stack item'
}: {
  stackItems: Uint8Array[];
  stackLabel?: string;
  stackItemLabel?: string;
}): void {
  if (stackItems.length > MAX_STACK_SIZE)
    throw new Error(
      `Error: ${stackLabel} has too many items, ${stackItems.length} is larger than ${MAX_STACK_SIZE}`
    );

  for (const stackItem of stackItems) {
    if (stackItem.length > MAX_SCRIPT_ELEMENT_SIZE)
      throw new Error(
        `Error: ${stackItemLabel} is too large, ${stackItem.length} bytes is larger than ${MAX_SCRIPT_ELEMENT_SIZE} bytes`
      );
  }
}

export function assertWitnessV0SatisfactionResourceLimits({
  stackItems
}: {
  stackItems: Uint8Array[];
}): void {
  assertConsensusStackResourceLimits({ stackItems });

  if (stackItems.length > MAX_STANDARD_P2WSH_STACK_ITEMS)
    throw new Error(
      `Error: witness stack has too many items, ${stackItems.length} is larger than ${MAX_STANDARD_P2WSH_STACK_ITEMS}`
    );

  for (const stackItem of stackItems) {
    if (stackItem.length > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
      throw new Error(
        `Error: witness stack item exceeds standard policy, ${stackItem.length} bytes is larger than ${MAX_STANDARD_P2WSH_STACK_ITEM_SIZE} bytes`
      );
  }
}

export function assertTaprootScriptPathSatisfactionResourceLimits({
  stackItems
}: {
  stackItems: Uint8Array[];
}): void {
  assertConsensusStackResourceLimits({
    stackItems,
    stackLabel: 'taproot script-path stack',
    stackItemLabel: 'taproot script-path stack item'
  });

  // Standardness policy for tapscript (leaf version 0xc0): <= 80 bytes.
  for (const stackItem of stackItems) {
    if (stackItem.length > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE)
      throw new Error(
        `Error: taproot script-path stack item exceeds standard policy, ${stackItem.length} bytes is larger than ${MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE} bytes`
      );
  }
}

export function assertP2shScriptSigStandardSize({
  scriptSatisfaction,
  redeemScript,
  network
}: {
  scriptSatisfaction: Uint8Array;
  redeemScript: Uint8Array;
  network: Network;
}): void {
  const scriptSig = p2sh({
    redeem: { input: scriptSatisfaction, output: redeemScript, network },
    network
  }).input;
  if (!scriptSig)
    throw new Error(`Error: could not build scriptSig from satisfaction`);
  if (scriptSig.length > MAX_STANDARD_SCRIPTSIG_SIZE)
    throw new Error(
      `Error: scriptSig is too large, ${scriptSig.length} bytes is larger than ${MAX_STANDARD_SCRIPTSIG_SIZE} bytes`
    );
}
