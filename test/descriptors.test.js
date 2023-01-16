//TODO: test invalid network / descriptor combination
import { address } from '../index';
import { fixtures } from './fixtures/descriptors';
//Use tests from here: https://min.sc/

//"pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1'/2h/3H/4/*H)"
//'sh(wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))'
describe('address', () => {
  test('address', () => {
    for (const dFixture of fixtures.descriptors) {
      const desc = dFixture.xDesc.replace('*', dFixture.index);
      expect(address({ desc, network: dFixture.network })).toEqual(
        dFixture.address
      );
    }
  });
});
