// Distributed under the MIT software license

import { encodingLength } from 'varuint-bitcoin';
import type { PartialSig } from 'bip174';
import type { OutputInstance } from '../../dist';

export const isSegwitTx = (inputs: Array<OutputInstance>): boolean =>
  inputs.some(input => input.isSegwit());

// Same implementation as in @bitcoinerlab/coinselect.
export function vsize(
  inputs: Array<OutputInstance>,
  outputs: Array<OutputInstance>,
  signaturesPerInput?: Array<Array<PartialSig>>
): number {
  const isSegwitTxValue = isSegwitTx(inputs);

  let totalWeight = 0;
  inputs.forEach((input, index) => {
    if (signaturesPerInput) {
      const signatures = signaturesPerInput[index];
      if (!signatures)
        throw new Error(`signaturesPerInput not defined for ${index}`);
      totalWeight += input.inputWeight(isSegwitTxValue, signatures);
    } else
      totalWeight += input.inputWeight(
        isSegwitTxValue,
        'DANGEROUSLY_USE_FAKE_SIGNATURES'
      );
  });

  outputs.forEach(output => {
    totalWeight += output.outputWeight();
  });

  if (isSegwitTxValue) totalWeight += 2;

  totalWeight += 8 * 4;
  totalWeight += encodingLength(inputs.length) * 4;
  totalWeight += encodingLength(outputs.length) * 4;

  return Math.ceil(totalWeight / 4);
}
