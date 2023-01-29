// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { DescriptorsFactory } from '../dist/index';
import { fixtures as customFixtures } from './fixtures/custom';
import { fixtures as bitcoinCoreFixtures } from './fixtures/bitcoinCore';
import * as ecc from '@bitcoinerlab/secp256k1';
const descriptors = DescriptorsFactory(ecc);

for (const fixtures of [customFixtures, bitcoinCoreFixtures]) {
  describe(`Parse valid ${
    fixtures === customFixtures ? 'custom fixtures' : 'Bitcoin Core fixtures'
  }`, () => {
    for (const fixture of fixtures.valid) {
      test(`Parse valid ${fixture.desc}`, () => {
        const parsed = descriptors.parse(fixture);
        if (!fixture.script && !fixture.address)
          throw new Error(`Error: pass a valid test for ${fixture.desc}`);
        if (fixture.script) {
          expect(parsed.output.toString('hex')).toEqual(fixture.script);
        }
        if (fixture.address) {
          expect(parsed.address).toEqual(fixture.address);
        }
      });
    }
  });
  describe(`Parse invalid ${
    fixtures === customFixtures ? 'custom fixtures' : 'Bitcoin Core fixtures'
  }`, () => {
    for (const fixture of fixtures.invalid) {
      test(`Parse invalid ${fixture.desc}`, () => {
        if (typeof fixture.throw !== 'string') {
          expect(() => {
            descriptors.parse(fixture);
          }).toThrow();
        } else {
          expect(() => {
            descriptors.parse(fixture);
          }).toThrow(fixture.throw);
        }
      });
    }
  });
}
