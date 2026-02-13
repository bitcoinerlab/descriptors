// Distributed under the MIT software license

import { script as bscript, networks, Network } from 'bitcoinjs-lib';
import {
  findScriptPath,
  tapleafHash,
  toHashTree,
  tweakKey
} from './bitcoinjs-lib-internals';
import { encodingLength } from 'varuint-bitcoin';
import { compare, concat, toHex } from 'uint8array-tools';
import type { BIP32API } from 'bip32';
import type { ECPairAPI } from 'ecpair';
import type { PartialSig, TapBip32Derivation } from 'bip174';
import type { Taptree } from 'bitcoinjs-lib/src/cjs/types';
import type { ExpansionMap, KeyInfo, Preimage, TimeConstraints } from './types';
import {
  expandMiniscript,
  miniscript2Script,
  satisfyMiniscript
} from './miniscript';
import type { TapLeafInfo, TapTreeInfoNode, TapTreeNode } from './tapTree';
import {
  MAX_TAPTREE_DEPTH,
  assertTapTreeDepth,
  collectTapTreeLeaves,
  selectTapLeafCandidates
} from './tapTree';
import { assertTaprootScriptPathSatisfactionResourceLimits } from './resourceLimits';

const TAPROOT_LEAF_VERSION_TAPSCRIPT = 0xc0;

export type TaprootLeafSatisfaction = {
  leaf: TapLeafInfo;
  depth: number;
  tapLeafHash: Uint8Array;
  scriptSatisfaction: Uint8Array;
  stackItems: Uint8Array[];
  nLockTime: number | undefined;
  nSequence: number | undefined;
  totalWitnessSize: number;
};

export type TaprootPsbtLeafMetadata = {
  leaf: TapLeafInfo;
  depth: number;
  tapLeafHash: Uint8Array;
  controlBlock: Uint8Array;
};

function expandTaprootMiniscript({
  miniscript,
  network = networks.bitcoin,
  BIP32,
  ECPair
}: {
  miniscript: string;
  network?: Network;
  BIP32: BIP32API;
  ECPair: ECPairAPI;
}): {
  expandedMiniscript: string;
  expansionMap: ExpansionMap;
} {
  return expandMiniscript({
    miniscript,
    isSegwit: true,
    isTaproot: true,
    network,
    BIP32,
    ECPair
  });
}

/**
 * Compiles a taproot miniscript tree into per-leaf metadata.
 * Each leaf contains its expanded miniscript, expansion map, compiled tapscript
 * and leaf version. This keeps the taproot script-path data ready for
 * satisfactions and witness building.
 */
export function buildTapTreeInfo({
  tapTree,
  network = networks.bitcoin,
  BIP32,
  ECPair
}: {
  tapTree: TapTreeNode;
  network?: Network;
  BIP32: BIP32API;
  ECPair: ECPairAPI;
}): TapTreeInfoNode {
  // Defensive: parseTapTreeExpression() already enforces this for descriptor
  // strings, but buildTapTreeInfo is exported and can be called directly.
  assertTapTreeDepth(tapTree);

  if ('miniscript' in tapTree) {
    const miniscript = tapTree.miniscript;
    const { expandedMiniscript, expansionMap } = expandTaprootMiniscript({
      miniscript,
      network,
      BIP32,
      ECPair
    });
    const tapScript = miniscript2Script({
      expandedMiniscript,
      expansionMap,
      tapscript: true
    });
    return {
      miniscript,
      expandedMiniscript,
      expansionMap,
      tapScript,
      version: TAPROOT_LEAF_VERSION_TAPSCRIPT
    };
  }
  return {
    left: buildTapTreeInfo({ tapTree: tapTree.left, network, BIP32, ECPair }),
    right: buildTapTreeInfo({ tapTree: tapTree.right, network, BIP32, ECPair })
  };
}

export function tapTreeInfoToScriptTree(tapTreeInfo: TapTreeInfoNode): Taptree {
  if ('miniscript' in tapTreeInfo) {
    return {
      output: tapTreeInfo.tapScript,
      version: tapTreeInfo.version
    };
  }
  return [
    tapTreeInfoToScriptTree(tapTreeInfo.left),
    tapTreeInfoToScriptTree(tapTreeInfo.right)
  ];
}

/**
 * Builds taproot PSBT leaf metadata for every leaf in a `tapTreeInfo`.
 *
 * For each leaf, this function computes:
 * - `tapLeafHash`: BIP341 leaf hash of tapscript + leaf version
 * - `depth`: leaf depth in the tree (root children have depth 1)
 * - `controlBlock`: script-path proof used in PSBT `tapLeafScript`
 *
 * The control block layout is:
 *
 * ```text
 * [1-byte (leafVersion | parity)] [32-byte internal key]
 * [32-byte sibling hash #1] ... [32-byte sibling hash #N]
 * ```
 *
 * where:
 * - `parity` is derived from tweaking the internal key with the tree root
 * - sibling hashes are the merkle path from that leaf to the root
 *
 * Example tree:
 *
 * ```text
 *         root
 *        /    \
 *      L1      L2
 *             /  \
 *           L3    L4
 * ```
 *
 * Depths:
 * - L1 depth = 1
 * - L3 depth = 2
 * - L4 depth = 2
 *
 * Conceptual output:
 *
 * ```text
 * [
 *   L1 -> { depth: 1, tapLeafHash: h1, controlBlock: [v|p, ik, hash(L2)] }
 *   L3 -> { depth: 2, tapLeafHash: h3, controlBlock: [v|p, ik, hash(L4), hash(L1)] }
 *   L4 -> { depth: 2, tapLeafHash: h4, controlBlock: [v|p, ik, hash(L3), hash(L1)] }
 * ]
 * ```
 *
 * Legend:
 * - `ik`: the 32-byte internal key placed in the control block.
 * - `hash(X)`: the merkle sibling hash at each level when proving leaf `X`.
 *
 * Note: in this diagram, `L2` is a branch node (right subtree), not a leaf,
 * so `hash(L2) = TapBranch(hash(L3), hash(L4))`.
 *
 * Notes:
 * - Leaves are returned in deterministic left-first order.
 * - One metadata entry is returned per leaf.
 * - `controlBlock.length === 33 + 32 * depth`.
 * - Throws if internal key is invalid or merkle path cannot be found.
 *
 * Typical usage:
 * - Convert this metadata into PSBT `tapLeafScript[]` entries
 *   for all leaves.
 */
export function buildTaprootLeafPsbtMetadata({
  tapTreeInfo,
  internalPubkey
}: {
  tapTreeInfo: TapTreeInfoNode;
  internalPubkey: Uint8Array;
}): TaprootPsbtLeafMetadata[] {
  const normalizedInternalPubkey = normalizeTaprootPubkey(internalPubkey);
  const scriptTree = tapTreeInfoToScriptTree(tapTreeInfo);
  const hashTree = toHashTree(scriptTree);
  const tweaked = tweakKey(normalizedInternalPubkey, hashTree.hash);
  if (!tweaked) throw new Error(`Error: invalid taproot internal pubkey`);

  return collectTapTreeLeaves(tapTreeInfo).map(({ leaf, depth }) => {
    if (depth > MAX_TAPTREE_DEPTH)
      throw new Error(
        `Error: taproot tree depth is too large, ${depth} is larger than ${MAX_TAPTREE_DEPTH}`
      );

    const tapLeafHash = tapleafHash({
      output: leaf.tapScript,
      version: leaf.version
    });
    const merklePath = findScriptPath(hashTree, tapLeafHash);
    if (!merklePath)
      throw new Error(
        `Error: could not build controlBlock for taproot leaf ${leaf.miniscript}`
      );
    // controlBlock[0] packs:
    // - leaf version (high bits), and
    // - parity of the tweaked output key Q = P + t*G (low bit).
    // `normalizedInternalPubkey` is x-only P, so parity is not encoded there.
    // BIP341 requires carrying Q parity in controlBlock[0].
    const controlBlock = concat([
      Uint8Array.from([leaf.version | tweaked.parity]),
      normalizedInternalPubkey,
      ...merklePath
    ]);
    return { leaf, depth, tapLeafHash, controlBlock };
  });
}

/**
 * Builds PSBT `tapBip32Derivation` entries for taproot script-path spends.
 *
 * Leaf keys include the list of tapleaf hashes where they appear.
 * If `internalKeyInfo` has derivation data, it is included with empty
 * `leafHashes`.
 *
 * Example tree:
 *
 * ```text
 *         root
 *        /    \
 *      L1      L2
 *
 * L1 uses key A
 * L2 uses key A and key B
 *
 * h1 = tapleafHash(L1)
 * h2 = tapleafHash(L2)
 * ```
 *
 * Then output is conceptually:
 *
 * ```text
 * [
 *   key A -> leafHashes [h1, h2]
 *   key B -> leafHashes [h2]
 *   internal key -> leafHashes []
 * ]
 * ```
 *
 * Notes:
 * - Keys missing `masterFingerprint` or `path` are skipped.
 * - Duplicate pubkeys are merged.
 * - If the same pubkey appears with conflicting derivation metadata,
 *   this function throws.
 * - Output and `leafHashes` are sorted deterministically.
 */
export function buildTaprootBip32Derivations({
  tapTreeInfo,
  internalKeyInfo
}: {
  tapTreeInfo: TapTreeInfoNode;
  internalKeyInfo?: KeyInfo;
}): TapBip32Derivation[] {
  type DerivationEntry = {
    masterFingerprint: Uint8Array;
    pubkey: Uint8Array;
    path: string;
    leafHashes: Map<string, Uint8Array>;
  };

  const entries = new Map<string, DerivationEntry>();

  const updateAndInsert = ({
    pubkey,
    masterFingerprint,
    path,
    leafHash
  }: {
    pubkey: Uint8Array;
    masterFingerprint: Uint8Array;
    path: string;
    leafHash?: Uint8Array;
  }): void => {
    const normalizedPubkey = normalizeTaprootPubkey(pubkey);
    const pubkeyHex = toHex(normalizedPubkey);
    const current = entries.get(pubkeyHex);
    if (!current) {
      const next: DerivationEntry = {
        masterFingerprint,
        pubkey: normalizedPubkey,
        path,
        leafHashes: new Map<string, Uint8Array>()
      };
      if (leafHash) next.leafHashes.set(toHex(leafHash), leafHash);
      entries.set(pubkeyHex, next);
      return;
    }

    if (
      compare(current.masterFingerprint, masterFingerprint) !== 0 ||
      current.path !== path
    ) {
      throw new Error(
        `Error: inconsistent taproot key derivation metadata for pubkey ${pubkeyHex}`
      );
    }
    if (leafHash) current.leafHashes.set(toHex(leafHash), leafHash);
  };

  const leaves = collectTapTreeLeaves(tapTreeInfo);
  for (const { leaf } of leaves) {
    const leafHash = tapleafHash({
      output: leaf.tapScript,
      version: leaf.version
    });
    for (const keyInfo of Object.values(leaf.expansionMap)) {
      if (!keyInfo.pubkey || !keyInfo.masterFingerprint || !keyInfo.path)
        continue;
      updateAndInsert({
        pubkey: keyInfo.pubkey,
        masterFingerprint: keyInfo.masterFingerprint,
        path: keyInfo.path,
        leafHash
      });
    }
  }

  if (
    internalKeyInfo?.pubkey &&
    internalKeyInfo.masterFingerprint &&
    internalKeyInfo.path
  ) {
    updateAndInsert({
      pubkey: internalKeyInfo.pubkey,
      masterFingerprint: internalKeyInfo.masterFingerprint,
      path: internalKeyInfo.path
    });
  }

  return [...entries.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(
      ([, entry]): TapBip32Derivation => ({
        masterFingerprint: entry.masterFingerprint,
        pubkey: entry.pubkey,
        path: entry.path,
        leafHashes: [...entry.leafHashes.entries()]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([, leafHash]) => leafHash)
      })
    );
}

function varSliceSize(someScript: Uint8Array): number {
  const length = someScript.length;
  return encodingLength(length) + length;
}

function vectorSize(someVector: Uint8Array[]): number {
  const length = someVector.length;
  return (
    encodingLength(length) +
    someVector.reduce((sum, witness) => sum + varSliceSize(witness), 0)
  );
}

function witnessStackSize(witness: Uint8Array[]): number {
  return vectorSize(witness);
}

function estimateTaprootWitnessSize({
  stackItems,
  tapScript,
  depth
}: {
  stackItems: Uint8Array[];
  tapScript: Uint8Array;
  depth: number;
}): number {
  if (depth > MAX_TAPTREE_DEPTH)
    throw new Error(
      `Error: taproot tree depth is too large, ${depth} is larger than ${MAX_TAPTREE_DEPTH}`
    );
  const controlBlock = new Uint8Array(33 + 32 * depth);
  return witnessStackSize([...stackItems, tapScript, controlBlock]);
}

export function normalizeTaprootPubkey(pubkey: Uint8Array): Uint8Array {
  if (pubkey.length === 32) return pubkey;
  if (pubkey.length === 33) return pubkey.slice(1, 33);
  throw new Error(`Error: invalid taproot pubkey length`);
}

/**
 * Computes satisfactions for taproot script-path leaves.
 *
 * If `tapLeaf` is undefined, all satisfiable leaves are returned. If `tapLeaf`
 * is provided, only that leaf is considered.
 *
 * Callers are expected to pass real signatures, or fake signatures generated
 * during planning. See satisfyMiniscript() for how timeConstraints keep the
 * chosen leaf consistent between planning and signing.
 */
export function collectTaprootLeafSatisfactions({
  tapTreeInfo,
  preimages,
  signatures,
  timeConstraints,
  tapLeaf
}: {
  tapTreeInfo: TapTreeInfoNode;
  preimages: Preimage[];
  signatures: PartialSig[];
  timeConstraints?: TimeConstraints;
  tapLeaf?: Uint8Array | string;
}): TaprootLeafSatisfaction[] {
  const candidates = selectTapLeafCandidates({
    tapTreeInfo,
    ...(tapLeaf !== undefined ? { tapLeaf } : {})
  });

  const getLeafPubkeys = (leaf: TapLeafInfo): Uint8Array[] => {
    return Object.values(leaf.expansionMap).map(keyInfo => {
      if (!keyInfo.pubkey)
        throw new Error(`Error: taproot leaf key missing pubkey`);
      return normalizeTaprootPubkey(keyInfo.pubkey);
    });
  };

  const resolveLeafSignatures = (leaf: TapLeafInfo): PartialSig[] => {
    const leafPubkeys = getLeafPubkeys(leaf);
    const leafPubkeySet = new Set(leafPubkeys.map(pubkey => toHex(pubkey)));

    return signatures
      .map((sig: PartialSig) => ({
        pubkey: normalizeTaprootPubkey(sig.pubkey),
        signature: sig.signature
      }))
      .filter((sig: PartialSig) => leafPubkeySet.has(toHex(sig.pubkey)));
  };

  const satisfactions: TaprootLeafSatisfaction[] = [];
  for (const candidate of candidates) {
    const { leaf } = candidate;
    const leafSignatures = resolveLeafSignatures(leaf);
    try {
      const { scriptSatisfaction, nLockTime, nSequence } = satisfyMiniscript({
        expandedMiniscript: leaf.expandedMiniscript,
        expansionMap: leaf.expansionMap,
        signatures: leafSignatures,
        preimages,
        ...(timeConstraints !== undefined ? { timeConstraints } : {}),
        tapscript: true
      });
      const satisfactionStackItems = bscript.toStack(scriptSatisfaction);
      assertTaprootScriptPathSatisfactionResourceLimits({
        stackItems: satisfactionStackItems
      });
      const totalWitnessSize = estimateTaprootWitnessSize({
        stackItems: satisfactionStackItems,
        tapScript: leaf.tapScript,
        depth: candidate.depth
      });
      satisfactions.push({
        leaf,
        depth: candidate.depth,
        tapLeafHash: candidate.tapLeafHash,
        scriptSatisfaction,
        stackItems: satisfactionStackItems,
        nLockTime,
        nSequence,
        totalWitnessSize
      });
    } catch (error) {
      if (tapLeaf !== undefined) throw error;
    }
  }

  if (satisfactions.length === 0)
    throw new Error(`Error: no satisfiable taproot leaves found`);

  return satisfactions;
}

/**
 * Selects the taproot leaf satisfaction with the smallest total witness size.
 * Assumes the input list is in left-first tree order for deterministic ties.
 */
export function selectBestTaprootLeafSatisfaction(
  satisfactions: TaprootLeafSatisfaction[]
): TaprootLeafSatisfaction {
  return satisfactions.reduce((best, current) => {
    if (!best) return current;
    if (current.totalWitnessSize < best.totalWitnessSize) return current;
    return best;
  });
}

/**
 * Collects a unique set of taproot leaf pubkeys (x-only) across the tree.
 * This is useful for building fake signatures when no signer subset is given.
 */
export function collectTapTreePubkeys(
  tapTreeInfo: TapTreeInfoNode
): Uint8Array[] {
  const pubkeySet = new Set<string>();
  const pubkeys: Uint8Array[] = [];
  const leaves = collectTapTreeLeaves(tapTreeInfo);
  for (const entry of leaves) {
    for (const keyInfo of Object.values(entry.leaf.expansionMap)) {
      if (!keyInfo.pubkey)
        throw new Error(`Error: taproot leaf key missing pubkey`);
      const normalized = normalizeTaprootPubkey(keyInfo.pubkey);
      const hex = toHex(normalized);
      if (pubkeySet.has(hex)) continue;
      pubkeySet.add(hex);
      pubkeys.push(normalized);
    }
  }
  return pubkeys;
}

/**
 * Returns the best satisfaction for a taproot tree, by witness size.
 *
 * If `tapLeaf` is provided, only that leaf is considered. If `tapLeaf` is a
 * bytes, it is treated as a tapLeafHash and must match exactly one leaf. If
 * `tapLeaf` is a string, it is treated as a miniscript leaf and must match
 * exactly one leaf (whitespace-insensitive).
 *
 * This function is typically called twice:
 * 1) Planning pass: call it with fake signatures (built by the caller) to
 *    choose the best leaf without requiring user signatures.
 * 2) Signing pass: call it again with real signatures and the timeConstraints
 *    returned from the first pass (see satisfyMiniscript() for why this keeps
 *    the chosen leaf consistent between planning and signing).
 */
export function satisfyTapTree({
  tapTreeInfo,
  signatures,
  preimages,
  tapLeaf,
  timeConstraints
}: {
  tapTreeInfo: TapTreeInfoNode;
  signatures: PartialSig[];
  preimages: Preimage[];
  tapLeaf?: Uint8Array | string;
  timeConstraints?: TimeConstraints;
}): TaprootLeafSatisfaction {
  const satisfactions = collectTaprootLeafSatisfactions({
    tapTreeInfo,
    preimages,
    signatures,
    ...(tapLeaf !== undefined ? { tapLeaf } : {}),
    ...(timeConstraints !== undefined ? { timeConstraints } : {})
  });
  return selectBestTaprootLeafSatisfaction(satisfactions);
}
