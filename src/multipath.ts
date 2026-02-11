/**
 * Replaces the receive/change shorthand `/**` with its canonical multipath
 * representation `/<0;1>/*`.
 */
function expandReceiveChangeShorthand(descriptor: string): string {
  return descriptor.replace(/\/\*\*/g, '/<0;1>/*');
}

type MultipathTupleMatch = {
  token: string;
  tupleBody: string;
  values: number[];
};

/**
 * Parses a multipath tuple body from `<...>`.
 *
 * This implementation intentionally accepts only decimal numbers (no hardened
 * suffixes) and enforces strict left-to-right increase as a safety feature to
 * catch likely human errors such as `<1;0>`.
 */
function parseMultipathTuple(tupleBody: string): number[] {
  const parts = tupleBody.split(';');
  if (parts.length < 2)
    throw new Error(
      `Error: multipath tuple must contain at least 2 values, got <${tupleBody}>`
    );

  const values = parts.map(part => {
    if (!/^(0|[1-9]\d*)$/.test(part))
      throw new Error(
        `Error: multipath tuple values must be decimal numbers, got <${tupleBody}>`
      );
    const value = Number(part);
    if (!Number.isSafeInteger(value))
      throw new Error(
        `Error: multipath tuple value overflow, got <${tupleBody}>`
      );
    return value;
  });

  for (let i = 1; i < values.length; i++) {
    const prev = values[i - 1];
    const current = values[i];
    if (prev === undefined || current === undefined)
      throw new Error(`Error: invalid multipath tuple <${tupleBody}>`);
    if (current <= prev)
      throw new Error(
        `Error: multipath tuple values must be strictly increasing from left to right, got <${tupleBody}>`
      );
  }

  return values;
}

/**
 * Resolves all multipath tuple segments (for example `/<0;1>/*`) in lockstep
 * using the provided `change` value.
 *
 * - `/**` is first canonicalized to `/<0;1>/*`.
 * - All tuples in the descriptor must have the same cardinality.
 * - Tuple values must be strictly increasing decimal numbers.
 * - `change` must match one of the values in each tuple.
 */
export function resolveMultipathDescriptor({
  descriptor,
  change
}: {
  descriptor: string;
  change?: number;
}): string {
  const canonicalDescriptor = expandReceiveChangeShorthand(descriptor);

  const tupleMatches: MultipathTupleMatch[] = Array.from(
    canonicalDescriptor.matchAll(/\/<([^<>]+)>/g),
    match => ({
      token: match[0],
      tupleBody: match[1]!,
      values: parseMultipathTuple(match[1]!)
    })
  );

  if (tupleMatches.length === 0) return canonicalDescriptor;

  if (change === undefined)
    throw new Error(`Error: change was not provided for multipath descriptor`);
  if (!Number.isInteger(change) || change < 0)
    throw new Error(`Error: invalid change ${change}`);

  const tupleSize = tupleMatches[0]?.values.length;
  if (!tupleSize) throw new Error(`Error: invalid multipath tuple`);

  for (const tupleMatch of tupleMatches) {
    if (tupleMatch.values.length !== tupleSize)
      throw new Error(
        `Error: all multipath tuples must have the same number of options`
      );
  }

  let resolvedDescriptor = canonicalDescriptor;
  for (const tupleMatch of tupleMatches) {
    if (!tupleMatch.values.includes(change))
      throw new Error(
        `Error: change ${change} not found in multipath tuple <${tupleMatch.tupleBody}>`
      );

    resolvedDescriptor = resolvedDescriptor.replaceAll(
      tupleMatch.token,
      `/${change}`
    );
  }

  return resolvedDescriptor;
}
