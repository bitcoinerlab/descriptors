// NOTE: This uses an internal bitcoinjs-lib module. Consider adding a local wrapper.
import { tapleafHash } from './bitcoinjs-lib-internals';
import { compare } from 'uint8array-tools';
import { splitTopLevelComma } from './parseUtils';
import type { ExpansionMap } from './types';

export type TreeNode<TLeaf> =
  | TLeaf
  | { left: TreeNode<TLeaf>; right: TreeNode<TLeaf> };

export type TapLeaf = {
  miniscript: string;
};

export type TapTreeNode = TreeNode<TapLeaf>;

export type TapLeafInfo = {
  miniscript: string;
  expandedMiniscript: string;
  expansionMap: ExpansionMap;
  tapScript: Uint8Array;
  version: number;
};

export type TapTreeInfoNode = TreeNode<TapLeafInfo>;

export type TapLeafSelection = {
  leaf: TapLeafInfo;
  depth: number;
  tapLeafHash: Uint8Array;
};

// See BIP341 control block limits and Sipa's Miniscript "Resource limitations":
// https://bitcoin.sipa.be/miniscript/
// Taproot script path depth is encoded in the control block as 32-byte hashes,
// with consensus max depth 128.
export const MAX_TAPTREE_DEPTH = 128;

function tapTreeMaxDepth(tapTree: TapTreeNode, depth = 0): number {
  if ('miniscript' in tapTree) return depth;
  return Math.max(
    tapTreeMaxDepth(tapTree.left, depth + 1),
    tapTreeMaxDepth(tapTree.right, depth + 1)
  );
}

export function assertTapTreeDepth(tapTree: TapTreeNode): void {
  const maxDepth = tapTreeMaxDepth(tapTree);
  if (maxDepth > MAX_TAPTREE_DEPTH)
    throw new Error(
      `Error: taproot tree depth is too large, ${maxDepth} is larger than ${MAX_TAPTREE_DEPTH}`
    );
}

/**
 * Collects taproot leaf metadata with depth from a tree.
 * Traversal is left-first, following the order of `{left,right}` in the
 * expression so tie-breaks are deterministic.
 *
 * Example tree:
 * ```
 * {pk(A),{pk(B),pk(C)}}
 * ```
 * Visual shape:
 * ```
 *         root
 *        /    \
 *     pk(A)  branch
 *            /   \
 *         pk(B) pk(C)
 * ```
 * Collected leaves with depth:
 * ```
 * [
 *   { leaf: pk(A), depth: 1 },
 *   { leaf: pk(B), depth: 2 },
 *   { leaf: pk(C), depth: 2 }
 * ]
 * ```
 */
export function collectTapTreeLeaves(
  tapTreeInfo: TapTreeInfoNode
): Array<{ leaf: TapLeafInfo; depth: number }> {
  const leaves: Array<{ leaf: TapLeafInfo; depth: number }> = [];
  const walk = (node: TapTreeInfoNode, depth: number) => {
    if ('miniscript' in node) {
      leaves.push({ leaf: node, depth });
      return;
    }
    walk(node.left, depth + 1);
    walk(node.right, depth + 1);
  };
  walk(tapTreeInfo, 0);
  return leaves;
}

function computeTapLeafHash(leaf: TapLeafInfo): Uint8Array {
  return tapleafHash({ output: leaf.tapScript, version: leaf.version });
}

function normalizeMiniscriptForMatch(miniscript: string): string {
  return miniscript.replace(/\s+/g, '');
}

/**
 * Resolves taproot leaf candidates based on an optional selector.
 *
 * If `tapLeaf` is undefined, all leaves are returned for auto-selection.
 * If `tapLeaf` is bytes, it is treated as a tapleaf hash and must match
 * exactly one leaf.
 * If `tapLeaf` is a string, it is treated as a miniscript leaf (raw, not
 * expanded). Matching is whitespace-insensitive. If the miniscript appears
 * more than once, this function throws an error.
 *
 * Example:
 * ```
 * const candidates = selectTapLeafCandidates({ tapTreeInfo, tapLeaf });
 * // tapLeaf can be undefined, bytes (tapleaf hash) or a miniscript string:
 * // f.ex.: 'pk(03bb...)'
 * ```
 */
export function selectTapLeafCandidates({
  tapTreeInfo,
  tapLeaf
}: {
  tapTreeInfo: TapTreeInfoNode;
  tapLeaf?: Uint8Array | string;
}): TapLeafSelection[] {
  const leaves = collectTapTreeLeaves(tapTreeInfo).map(({ leaf, depth }) => ({
    leaf,
    depth,
    tapLeafHash: computeTapLeafHash(leaf)
  }));

  if (tapLeaf === undefined) return leaves;

  if (tapLeaf instanceof Uint8Array) {
    const match = leaves.find(
      entry => compare(entry.tapLeafHash, tapLeaf) === 0
    );
    if (!match) throw new Error(`Error: tapleaf hash not found in tapTreeInfo`);
    return [match];
  }

  const normalizedSelector = normalizeMiniscriptForMatch(tapLeaf);
  const matches = leaves.filter(
    entry =>
      normalizeMiniscriptForMatch(entry.leaf.miniscript) === normalizedSelector
  );
  if (matches.length === 0)
    throw new Error(
      `Error: miniscript leaf not found in tapTreeInfo: ${tapLeaf}`
    );
  if (matches.length > 1)
    throw new Error(
      `Error: miniscript leaf is ambiguous in tapTreeInfo: ${tapLeaf}`
    );
  return matches;
}

function tapTreeError(expression: string): Error {
  return new Error(`Error: invalid taproot tree expression: ${expression}`);
}

/**
 * Splits the inner tree expression of a branch into left/right parts.
 * The input must be the contents inside `{}` (no outer braces).
 * Example: `pk(@0),{pk(@1),pk(@2)}` => left: `pk(@0)`, right: `{pk(@1),pk(@2)}`.
 */
function splitTapTreeExpression(expression: string): {
  left: string;
  right: string;
} {
  const result = splitTopLevelComma({ expression, onError: tapTreeError });
  if (!result) throw tapTreeError(expression);
  return result;
}

/**
 * Parses a single taproot tree node expression.
 * Examples:
 * - `pk(@0)` => { miniscript: 'pk(@0)' }
 * - `{pk(@0),pk(@1)}` => { left: { miniscript: 'pk(@0)' }, right: { miniscript: 'pk(@1)' } }
 * - `{pk(@0),{pk(@1),pk(@2)}}` =>
 *   {
 *     left: { miniscript: 'pk(@0)' },
 *     right: { left: { miniscript: 'pk(@1)' }, right: { miniscript: 'pk(@2)' } }
 *   }
 */
function parseTapTreeNode(expression: string): TapTreeNode {
  const trimmedExpression = expression.trim();
  if (!trimmedExpression) throw tapTreeError(expression);
  if (trimmedExpression.startsWith('{')) {
    if (!trimmedExpression.endsWith('}')) throw tapTreeError(expression);
    const inner = trimmedExpression.slice(1, -1).trim();
    if (!inner) throw tapTreeError(expression);
    const { left, right } = splitTapTreeExpression(inner);
    return {
      left: parseTapTreeNode(left),
      right: parseTapTreeNode(right)
    };
  }
  if (trimmedExpression.includes('{') || trimmedExpression.includes('}'))
    throw tapTreeError(expression);
  return { miniscript: trimmedExpression };
}

export function parseTapTreeExpression(expression: string): TapTreeNode {
  const trimmed = expression.trim();
  if (!trimmed) throw tapTreeError(expression);
  const tapTree = parseTapTreeNode(trimmed);
  assertTapTreeDepth(tapTree);
  return tapTree;
}
