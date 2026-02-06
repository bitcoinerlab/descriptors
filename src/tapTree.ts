export type TapLeaf = {
  miniscript: string;
};

export type TapBranch = {
  left: TapTreeNode;
  right: TapTreeNode;
};

export type TapTreeNode = TapLeaf | TapBranch;

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
  let braceDepth = 0;
  let parenDepth = 0;
  let commaIndex = -1;
  for (let i = 0; i < expression.length; i++) {
    const char = expression[i];
    if (!char) continue;
    if (char === '{') {
      braceDepth++;
    } else if (char === '}') {
      if (braceDepth === 0) throw tapTreeError(expression);
      braceDepth--;
    } else if (char === '(') {
      //Track miniscript argument lists so we don't split on commas inside them
      //to discard commas inside miniscripts, e.g.: and_v(pk(@0),pk(@1)),pk(@2)
      parenDepth++;
    } else if (char === ')') {
      if (parenDepth === 0) throw tapTreeError(expression);
      parenDepth--;
    } else if (char === ',') {
      if (braceDepth === 0 && parenDepth === 0) {
        if (commaIndex !== -1) throw tapTreeError(expression);
        commaIndex = i;
      }
    }
  }
  if (braceDepth !== 0 || parenDepth !== 0 || commaIndex === -1)
    throw tapTreeError(expression);
  const left = expression.slice(0, commaIndex).trim();
  const right = expression.slice(commaIndex + 1).trim();
  if (!left || !right) throw tapTreeError(expression);
  return { left, right };
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
  const trimmed = expression.trim();
  if (!trimmed) throw tapTreeError(expression);
  if (trimmed.startsWith('{')) {
    if (!trimmed.endsWith('}')) throw tapTreeError(expression);
    const inner = trimmed.slice(1, -1).trim();
    if (!inner) throw tapTreeError(expression);
    const { left, right } = splitTapTreeExpression(inner);
    return {
      left: parseTapTreeNode(left),
      right: parseTapTreeNode(right)
    };
  }
  if (trimmed.includes('{') || trimmed.includes('}'))
    throw tapTreeError(expression);
  return { miniscript: trimmed };
}

export function parseTapTreeExpression(expression: string): TapTreeNode {
  const trimmed = expression.trim();
  if (!trimmed) throw tapTreeError(expression);
  return parseTapTreeNode(trimmed);
}
