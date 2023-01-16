import { networks } from 'bitcoinjs-lib';
export const fixtures = {
  descriptors: [
    {
      network: networks.testnet,
      xDesc:
        "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)",
      index: 23,
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/23)" get_new_address
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.bitcoin,
      xDesc:
        "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/2/3/4/*)",
      index: 11,
      //bdk-cli -n bitcoin wallet -d "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/2/3/4/11)" get_new_address
      address: '1Dnsk4Tswt8D1whJBE2KBDc4mv6f3kZBGU'
    },
    {
      network: networks.regtest,
      xDesc:
        "sh(wpkh([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))",
      index: 11,
      //Generate truth using bdk:
      //bdk-cli -n regtest wallet -d "sh(wpkh([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/11))" get_new_address
      address: '2N2opuegAya5DpnKXb5E2hVRSaWQSXvje1D'
    },
    {
      network: networks.testnet,
      xDesc:
        "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))",
      index: 10,
      //Generate truth using bdk:
      //bdk-cli -n testnet wallet -d "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/10))))" get_new_address
      address: '2N6ZCmdLhVBqb2nCZnCCiaTP81jHP6mftUg'
    }
  ]
};
