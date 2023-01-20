// Copyright (c) 2023 Jose-Luis Landabaso
// Distributed under the MIT software license

import { DescriptorsFactory } from '../src/index';
import { fixtures } from './fixtures/descriptors';
import * as ecc from '@bitcoinerlab/secp256k1';
const descriptors = DescriptorsFactory(ecc);

describe('parse', () => {
  test('parse valid descriptors', () => {
    for (const fixture of fixtures.valid) {
      const parsed = descriptors.parse(fixture);
      if (fixture.outputScript) {
        expect(parsed.output.toString('hex')).toEqual(fixture.outputScript);
      }
      if (fixture.address) {
        expect(parsed.address).toEqual(fixture.address);
      }
    }
  });
  test('parse invalid descriptors', () => {
    for (const fixture of fixtures.invalid) {
      expect(() => {
        descriptors.parse(fixture);
      }).toThrow(fixture.throw);
    }
  });
});
