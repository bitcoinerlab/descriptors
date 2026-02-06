export function splitTopLevelComma({
  expression,
  onError
}: {
  expression: string;
  onError: (expression: string) => Error;
}): { left: string; right: string } | null {
  let braceDepth = 0;
  let parenDepth = 0;
  let commaIndex = -1;
  for (let i = 0; i < expression.length; i++) {
    const char = expression[i];
    if (!char) continue;
    if (char === '{') {
      braceDepth++;
    } else if (char === '}') {
      if (braceDepth === 0) throw onError(expression);
      braceDepth--;
    } else if (char === '(') {
      //Track miniscript argument lists so we don't split on commas inside them.
      parenDepth++;
    } else if (char === ')') {
      if (parenDepth === 0) throw onError(expression);
      parenDepth--;
    } else if (char === ',') {
      if (braceDepth === 0 && parenDepth === 0) {
        if (commaIndex !== -1) throw onError(expression);
        commaIndex = i;
      }
    }
  }
  if (braceDepth !== 0 || parenDepth !== 0) throw onError(expression);
  if (commaIndex === -1) return null;
  const left = expression.slice(0, commaIndex).trim();
  const right = expression.slice(commaIndex + 1).trim();
  if (!left || !right) throw onError(expression);
  return { left, right };
}
