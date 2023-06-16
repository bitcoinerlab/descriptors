// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { DescriptorsFactory } from '../dist';
import { fixtures as customFixtures } from './fixtures/custom';
import { fixtures as bitcoinCoreFixtures } from './fixtures/bitcoinCore';
import * as ecc from '@bitcoinerlab/secp256k1';
const { Descriptor, expand } = DescriptorsFactory(ecc);

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

        //TODO: This block below is only to generate thruth
        if (fixtures === customFixtures) {
          const cloneExpansionMap = obj =>
            Object.entries(obj).reduce((acc, [key, value]) => {
              acc[key] = [
                'keyExpression',
                'keyPath',
                'originPath',
                'path'
              ].reduce((subAcc, subKey) => {
                if (subKey in value) subAcc[subKey] = value[subKey];
                return subAcc;
              }, {});
              return acc;
            }, {});
          if (expansion.expansionMap) {
            console.log(fixture.expression, {
              expandedExpression: expansion.expandedExpression,
              expansionMap: cloneExpansionMap(expansion.expansionMap)
            });
          }
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
