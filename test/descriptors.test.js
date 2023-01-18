//TODO: test invalid network / descriptor combination
//TODO: test vectors: https://github.com/bitcoin/bitcoin/blob/master/src/test/descriptor_tests.cpp
import { parse } from '../src/index';
import { fixtures } from './fixtures/descriptors';
//TODO: get more tests from here: https://min.sc/

//"pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1'/2h/3H/4/*H)"
//'sh(wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))'
describe('parse', () => {
  test('parse', () => {
    for (const fixture of fixtures.valid) {
      const parsed = parse(fixture);
      if (fixture.script) {
        expect(parsed.output.toString('hex')).toEqual(fixture.script);
      }
      if (fixture.address) {
        expect(parsed.address).toEqual(fixture.address);
      }
    }
  });
});
