// Copyright (c) 2023 Jose-Luis Landabaso
// Distributed under the MIT software license

//console.log(
//  //Should be tjg09x5t
//  //https://reviews.bitcoinabc.org/D6600
//  descsum_create(
//    `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy,sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))`
//  )
//);
//console.log(descsum_create(`tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})`));
//console.log(descsum_create(desc));
//
//result should be: #02wpgw69
//https://bitcoin.stackexchange.com/questions/96728/how-to-manually-compute-a-deoutputScriptors-checksum
//console.log(DeoutputScriptorChecksum(`addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)`));
//
//
//console.log(descsum_create(`wpkh([9a6a2580/84'/1'/180']tpubDCMRAYcH71GibuLuWcDkwmmY1gXkXhf162QuEHxkMpZPSi7xck2eGQ6MRGKxNTeY8P1FiFTPCLA5x7qZpFx84fnnrNQFpSnUCwd1nPG8Mk9/0/*)`));
//console.log(descsum_check('addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)#dp90etnw'));
//console.log(descsum_check('addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)#02wpgw69'));
import { networks } from 'bitcoinjs-lib';
export const fixtures = {
  valid: [
    {
      desc: 'pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)',
      outputScript:
        '2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac',
      checksumRequired: false
    },
    {
      desc: "pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
      outputScript: '76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac',
      checksumRequired: false
    },
    {
      network: networks.testnet,
      desc: 'addr(tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss)',
      checksumRequired: false,
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.testnet,
      desc: "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)",
      checksumRequired: false,
      index: 23,
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/23)" get_new_address
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.testnet,
      desc: "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)#lj5cryhp",
      index: 23,
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/23)" get_new_address
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.bitcoin,
      note: 'This is a wif address',
      desc: "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)",
      checksumRequired: false,
      //bdk-cli -n bitcoin wallet -d "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)" get_new_address
      address: 'bc1qkk7jt9nx3hf05tlxc80vzmvxvamdh6jsfsph33'
    },
    {
      network: networks.bitcoin,
      desc: "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/2/3/4/*)",
      checksumRequired: false,
      index: 11,
      //bdk-cli -n bitcoin wallet -d "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/2/3/4/11)" get_new_address
      address: '1Dnsk4Tswt8D1whJBE2KBDc4mv6f3kZBGU'
    },
    {
      network: networks.regtest,
      desc: "sh(wpkh([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))",
      checksumRequired: false,
      index: 11,
      //Generate truth using bdk:
      //bdk-cli -n regtest wallet -d "sh(wpkh([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/11))" get_new_address
      address: '2N2opuegAya5DpnKXb5E2hVRSaWQSXvje1D'
    },
    {
      network: networks.testnet,
      desc: "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))",
      checksumRequired: false,
      index: 10,
      //Generate truth using bdk:
      //bdk-cli -n testnet wallet -d "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/10))))" get_new_address
      address: '2N6ZCmdLhVBqb2nCZnCCiaTP81jHP6mftUg'
    }
  ],
  invalid: [
    {
      network: networks.testnet,
      note: 'This is a wif address, note however that KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik corresponds to mainnet',
      desc: "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)",
      checksumRequired: false,
      //bdk-cli should throw here, but it does not :-/
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)" get_new_address
      address: 'tb1qkk7jt9nx3hf05tlxc80vzmvxvamdh6jsrk6y2z'
    }
  ]
};
