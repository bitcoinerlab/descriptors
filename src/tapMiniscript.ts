// Distributed under the MIT software license

import { script as bscript, networks, Network } from 'bitcoinjs-lib';
import {
  findScriptPath,
  tapleafHash,
  toHashTree,
  tweakKey
} from 'bitcoinjs-lib/src/payments/bip341';
import { encodingLength } from 'varuint-bitcoin';
import type { BIP32API } from 'bip32';
import type { ECPairAPI } from 'ecpair';
import type {
  PartialSig,
  TapBip32Derivation,
  TapLeafScript
} from 'bip174/src/lib/interfaces';
import type { Taptree } from 'bitcoinjs-lib/src/types';
import type { ExpansionMap, KeyInfo, Preimage, TimeConstraints } from './types';
import {
  expandMiniscript,
  miniscript2Script,
  satisfyMiniscript
} from './miniscript';
import type { TapLeafInfo, TapTreeInfoNode, TapTreeNode } from './tapTree';
import { collectTapTreeLeaves, selectTapLeafCandidates } from './tapTree';

const TAPROOT_LEAF_VERSION_TAPSCRIPT = 0xc0;

export type TaprootLeafSatisfaction = {
  leaf: TapLeafInfo;
  depth: number;
  tapLeafHash: Buffer;
  scriptSatisfaction: Buffer;
  stackItems: Buffer[];
  nLockTime: number | undefined;
  nSequence: number | undefined;
  totalWitnessSize: number;
};

export type TaprootPsbtLeafMetadata = {
  leaf: TapLeafInfo;
  depth: number;
  tapLeafHash: Buffer;
  controlBlock: Buffer;
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
  internalPubkey: Buffer;
}): TaprootPsbtLeafMetadata[] {
  const normalizedInternalPubkey = normalizeTaprootPubkey(internalPubkey);
  const scriptTree = tapTreeInfoToScriptTree(tapTreeInfo);
  const hashTree = toHashTree(scriptTree);
  const tweaked = tweakKey(normalizedInternalPubkey, hashTree.hash);
  if (!tweaked) throw new Error(`Error: invalid taproot internal pubkey`);

  return collectTapTreeLeaves(tapTreeInfo).map(({ leaf, depth }) => {
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
    const controlBlock = Buffer.concat([
      Buffer.from([leaf.version | tweaked.parity]),
      normalizedInternalPubkey,
      ...merklePath
    ]);
    return { leaf, depth, tapLeafHash, controlBlock };
  });
}

/**
 * Builds all `tapLeafScript` entries to be added in a PSBT input.
 */
export function buildTapLeafScripts({
  tapTreeInfo,
  internalPubkey
}: {
  tapTreeInfo: TapTreeInfoNode;
  internalPubkey: Buffer;
}): TapLeafScript[] {
  return buildTaprootLeafPsbtMetadata({ tapTreeInfo, internalPubkey }).map(
    ({ leaf, controlBlock }) => ({
      script: leaf.tapScript,
      leafVersion: leaf.version,
      controlBlock
    })
  );
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
    masterFingerprint: Buffer;
    pubkey: Buffer;
    path: string;
    leafHashes: Map<string, Buffer>;
  };

  const entries = new Map<string, DerivationEntry>();

  const updateAndInsert = ({
    pubkey,
    masterFingerprint,
    path,
    leafHash
  }: {
    pubkey: Buffer;
    masterFingerprint: Buffer;
    path: string;
    leafHash?: Buffer;
  }): void => {
    const normalizedPubkey = normalizeTaprootPubkey(pubkey);
    const pubkeyHex = normalizedPubkey.toString('hex');
    const current = entries.get(pubkeyHex);
    if (!current) {
      const next: DerivationEntry = {
        masterFingerprint,
        pubkey: normalizedPubkey,
        path,
        leafHashes: new Map<string, Buffer>()
      };
      if (leafHash) next.leafHashes.set(leafHash.toString('hex'), leafHash);
      entries.set(pubkeyHex, next);
      return;
    }

    if (
      !current.masterFingerprint.equals(masterFingerprint) ||
      current.path !== path
    ) {
      throw new Error(
        `Error: inconsistent taproot key derivation metadata for pubkey ${pubkeyHex}`
      );
    }
    if (leafHash) current.leafHashes.set(leafHash.toString('hex'), leafHash);
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

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;
  return encodingLength(length) + length;
}

function vectorSize(someVector: Buffer[]): number {
  const length = someVector.length;
  return (
    encodingLength(length) +
    someVector.reduce((sum, witness) => sum + varSliceSize(witness), 0)
  );
}

function witnessStackSize(witness: Buffer[]): number {
  return vectorSize(witness);
}

/**
 * Converts a satisfaction script into witness stack items.
 *
 * The satisfier gives us the unlocking data as a script (a sequence of push
 * opcodes and data). That format is still directly usable for legacy P2SH
 * (scriptSig), and bitcoinjs-lib accepts it for WSH for legacy reasons, so we
 * keep this representation to share the same miniscript pipeline across
 * sh/wsh/tr.
 *
 * For WSH and taproot, the actual spend uses a witness stack. This is a
 * different binary format stored in the transaction: a vector of byte strings,
 * each length-prefixed, plus an item count at the beginning. So we decompile
 * the (legacy) script into the raw stack items, which is what is finally used.
 *
 * Example satisfaction script: `<preimage> <sig> 0`
 * Script bytes:
 *   20 <preimage32> 40 <sig64> 00
 * where 0x20/0x40 are PUSH opcodes and 0x00 is OP_0 (push empty).
 *
 * Witness stack items (the way bitcoinjs-lib expects it):
 *   [ preimage, sig, empty ]
 *
 * These stack items are later serialized via witnessStackToScriptWitness(...),
 * and for taproot we then append tapScript and controlBlock:
 * [items..., tapScript, controlBlock].
 *
 * This is also useful for estimating witness size without finalizing a PSBT.
 */
function satisfactionToStackItems(scriptSatisfaction: Buffer): Buffer[] {
  const chunks = bscript.decompile(scriptSatisfaction);
  if (!chunks)
    throw new Error(`Error: could not decompile script satisfaction`);
  return chunks.map(chunk => {
    if (Buffer.isBuffer(chunk)) return chunk;
    if (typeof chunk !== 'number')
      throw new Error(`Error: invalid satisfaction chunk`);
    if (chunk < -1 || chunk > 16)
      throw new Error(
        `Error: satisfaction contains a non-push opcode (${chunk})`
      );
    if (chunk === 0) return Buffer.alloc(0);
    return bscript.number.encode(chunk);
  });
}

function estimateTaprootWitnessSize({
  stackItems,
  tapScript,
  depth
}: {
  stackItems: Buffer[];
  tapScript: Buffer;
  depth: number;
}): number {
  const controlBlock = Buffer.alloc(33 + 32 * depth, 0);
  return witnessStackSize([...stackItems, tapScript, controlBlock]);
}

export function normalizeTaprootPubkey(pubkey: Buffer): Buffer {
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
  tapLeaf?: Buffer | string;
}): TaprootLeafSatisfaction[] {
  const candidates = selectTapLeafCandidates({
    tapTreeInfo,
    ...(tapLeaf !== undefined ? { tapLeaf } : {})
  });

  const getLeafPubkeys = (leaf: TapLeafInfo): Buffer[] => {
    return Object.values(leaf.expansionMap).map(keyInfo => {
      if (!keyInfo.pubkey)
        throw new Error(`Error: taproot leaf key missing pubkey`);
      return normalizeTaprootPubkey(keyInfo.pubkey);
    });
  };

  const resolveLeafSignatures = (leaf: TapLeafInfo): PartialSig[] => {
    const leafPubkeys = getLeafPubkeys(leaf);
    const leafPubkeySet = new Set(
      leafPubkeys.map(pubkey => pubkey.toString('hex'))
    );

    return signatures
      .map((sig: PartialSig) => ({
        pubkey: normalizeTaprootPubkey(sig.pubkey),
        signature: sig.signature
      }))
      .filter((sig: PartialSig) =>
        leafPubkeySet.has(sig.pubkey.toString('hex'))
      );
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
      const stackItems = satisfactionToStackItems(scriptSatisfaction);
      const totalWitnessSize = estimateTaprootWitnessSize({
        stackItems,
        tapScript: leaf.tapScript,
        depth: candidate.depth
      });
      satisfactions.push({
        leaf,
        depth: candidate.depth,
        tapLeafHash: candidate.tapLeafHash,
        scriptSatisfaction,
        stackItems,
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
export function collectTapTreePubkeys(tapTreeInfo: TapTreeInfoNode): Buffer[] {
  const pubkeySet = new Set<string>();
  const pubkeys: Buffer[] = [];
  const leaves = collectTapTreeLeaves(tapTreeInfo);
  for (const entry of leaves) {
    for (const keyInfo of Object.values(entry.leaf.expansionMap)) {
      if (!keyInfo.pubkey)
        throw new Error(`Error: taproot leaf key missing pubkey`);
      const normalized = normalizeTaprootPubkey(keyInfo.pubkey);
      const hex = normalized.toString('hex');
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
 * Buffer, it is treated as a tapLeafHash and must match exactly one leaf. If
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
  tapLeaf?: Buffer | string;
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
