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
  tapScript: Buffer;
  version: number;
};

export type TapTreeInfoNode = TreeNode<TapLeafInfo>;

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
  return parseTapTreeNode(trimmed);
}
