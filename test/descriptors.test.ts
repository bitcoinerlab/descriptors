// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// This file still needs to be properly converted to Typescript:
/* eslint-disable @typescript-eslint/ban-ts-comment */
// @ts-nocheck
/* eslint-enable @typescript-eslint/ban-ts-comment */

import { DescriptorsFactory } from '../dist';
import { fixtures as customFixtures } from './fixtures/custom';
import { fixtures as bitcoinCoreFixtures } from './fixtures/bitcoinCore';
import * as ecc from '@bitcoinerlab/secp256k1';
const { Descriptor, expand } = DescriptorsFactory(ecc);

function partialDeepEqual(obj) {
  if (typeof obj === 'object' && obj !== null && obj.constructor === Object) {
    const newObj = {};
    for (const key in obj) {
      newObj[key] = partialDeepEqual(obj[key]);
    }
    return expect.objectContaining(newObj);
  } else {
    return obj;
  }
}

for (const fixtures of [customFixtures, bitcoinCoreFixtures]) {
  describe(`Parse valid ${
    fixtures === customFixtures ? 'custom fixtures' : 'Bitcoin Core fixtures'
  }`, () => {
    for (const fixture of fixtures.valid) {
      test(`Parse valid ${fixture.expression}`, () => {
        const descriptor = new Descriptor(fixture);
        let expansion;
        expect(() => {
          expansion = expand({
            expression: fixture.expression,
            network: fixture.network,
            allowMiniscriptInP2SH: fixture.allowMiniscriptInP2SH
          });
        }).not.toThrow();

        if (fixture.expansion) {
          expect(expansion).toEqual(partialDeepEqual(fixture.expansion));
        }

        if (!fixture.script && !fixture.address)
          throw new Error(`Error: pass a valid test for ${fixture.expression}`);
        if (fixture.script) {
          expect(descriptor.getScriptPubKey().toString('hex')).toEqual(
            fixture.script
          );
        }
        if (fixture.address) {
          expect(descriptor.getAddress()).toEqual(fixture.address);
        }
      });
    }
  });
  describe(`Parse invalid ${
    fixtures === customFixtures ? 'custom fixtures' : 'Bitcoin Core fixtures'
  }`, () => {
    for (const fixture of fixtures.invalid) {
      test(`Parse invalid ${fixture.expression}`, () => {
        if (typeof fixture.throw !== 'string') {
          expect(() => {
            new Descriptor(fixture);
          }).toThrow();
        } else {
          expect(() => {
            new Descriptor(fixture);
          }).toThrow(fixture.throw);
        }
      });
    }
  });
}
