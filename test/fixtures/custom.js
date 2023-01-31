// Copyright (c) 2023 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

// Some test vectors taken from:
//https://github.com/bitcoin/bitcoin/blob/master/src/test/descriptor_tests.cpp
//Other test vectors created using bdk-cli - https://github.com/bitcoindevkit/bdk-cli

//console.log(
//  //Should be tjg09x5t
//  //https://reviews.bitcoinabc.org/D6600
//  descsum_create(
//    `sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy,sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))`
//  )
//);
//console.log(descsum_create(`tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})`));
//console.log(descsum_create(expression));
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
      expression:
        'sh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))',
      address: '345X16vrwhSrbV4hp1AM5wqLh8s2kj6di4',
      note: 'bdk-cli -n bitcoin wallet -d "sh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))" get_new_address',
      checksumRequired: false
    },

    {
      expression:
        'sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))',
      address: '345X16vrwhSrbV4hp1AM5wqLh8s2kj6di4',
      note: 'using the pubkey instead of thw WIF of the test above; bdk-cli -n bitcoin wallet -d "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))" get_new_address',
      checksumRequired: false
    },
    {
      expression: 'pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)',
      script:
        '2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac',
      checksumRequired: false
    },
    {
      expression:
        "pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
      script: '76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac',
      checksumRequired: false
    },
    {
      network: networks.testnet,
      expression: 'addr(tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss)',
      checksumRequired: false,
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.testnet,
      expression:
        "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)",
      checksumRequired: false,
      index: 23,
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/23)" get_new_address
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.testnet,
      expression:
        "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)#lj5cryhp",
      index: 23,
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/23)" get_new_address
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.bitcoin,
      note: 'This is a wif address',
      expression:
        "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)",
      checksumRequired: false,
      //bdk-cli -n bitcoin wallet -d "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)" get_new_address
      address: 'bc1qkk7jt9nx3hf05tlxc80vzmvxvamdh6jsfsph33'
    },
    {
      network: networks.bitcoin,
      expression:
        "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/2/3/4/*)",
      checksumRequired: false,
      index: 11,
      //bdk-cli -n bitcoin wallet -d "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/2/3/4/11)" get_new_address
      address: '1Dnsk4Tswt8D1whJBE2KBDc4mv6f3kZBGU'
    },
    {
      network: networks.regtest,
      expression:
        "sh(wpkh([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))",
      checksumRequired: false,
      index: 11,
      //Generate truth using bdk:
      //bdk-cli -n regtest wallet -d "sh(wpkh([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/11))" get_new_address
      address: '2N2opuegAya5DpnKXb5E2hVRSaWQSXvje1D'
    },
    {
      network: networks.testnet,
      expression:
        "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))",
      checksumRequired: false,
      index: 10,
      //Generate truth using bdk:
      //bdk-cli -n testnet wallet -d "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/10))))" get_new_address
      address: '2N6ZCmdLhVBqb2nCZnCCiaTP81jHP6mftUg'
    },
    {
      network: networks.testnet,
      expression:
        "sh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*)))",
      checksumRequired: false,
      allowMiniscriptInP2SH: true,
      index: 10,
      //Generate truth using bdk:
      //bdk-cli -n testnet wallet -d "wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/10)))" get_new_address
      address: '2NEpsKYHiyLTik8Cvdj1eanQ8i1utbwR7ZH'
    },
    {
      network: networks.testnet,
      expression:
        "wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*)))",
      checksumRequired: false,
      index: 10,
      //Generate truth using bdk:
      //bdk-cli -n testnet wallet -d "wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/10)))" get_new_address
      address: 'tb1qsy5qmg66rv06xz3xcddkfdad82r67a6mnfq8w4lwmnxttcs3grjst7e48x'
    },
    {
      network: networks.testnet,
      expression:
        "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)#lj5cryhp",
      index: 23,
      note: 'it still works even if passing a checksum when not required',
      checksumRequired: false,
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/23)" get_new_address
      address: 'tb1q7a6n3dadstfjpp6p56nxklxac6efz0lyy0rgss'
    },
    {
      network: networks.bitcoin,
      note: 'Bitcoin Core test - https://github.com/bitcoin/bitcoin/blob/b5c88a547996776dbdc2e101bae9b67ac639fd02/src/test/descriptor_tests.cpp#L413',
      expression:
        'wsh(multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))',
      checksumRequired: false,
      script:
        '0020cb155486048b23a6da976d4c6fe071a2dbc8a7b57aaf225b8955f2e2a27b5f00'
    },
    {
      note: 'Bitcoin Core test - https://github.com/bitcoin/bitcoin/blob/b5c88a547996776dbdc2e101bae9b67ac639fd02/src/test/descriptor_tests.cpp#L442',
      expression:
        'wsh(multi(20,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f,L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD,KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK,L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU,KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i,L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ,KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE,KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF,KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap,KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3,KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP,KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8,L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9,KzRedjSwMggebB3VufhbzpYJnvHfHe9kPJSjCU5QpJdAW3NSZxYS,Kyjtp5858xL7JfeV4PNRCKy2t6XvgqNNepArGY9F9F1SSPqNEMs3,L2D4RLHPiHBidkHS8ftx11jJk1hGFELvxh8LoxNQheaGT58dKenW,KyLPZdwY4td98bKkXqEXTEBX3vwEYTQo1yyLjX2jKXA63GBpmSjv))',
      checksumRequired: false,
      script:
        '0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac',
      address: 'bc1qxa4asdzt3dhtu5z0lp00wsl25x4fyushsg3med5g06fh3mangxkqgf3se4'
    },
    {
      note: 'Bitcoin Core test - https://github.com/bitcoin/bitcoin/blob/b5c88a547996776dbdc2e101bae9b67ac639fd02/src/test/descriptor_tests.cpp#L442',
      expression:
        'wsh(multi(20,03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0,0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600,0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8,0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8,02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8,0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286,0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009,02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d,03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9,02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af,02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd,036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24,02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc,02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3,02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06,0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232,02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e,0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca,02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759,0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd))',
      checksumRequired: false,
      script:
        '0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac',
      address: 'bc1qxa4asdzt3dhtu5z0lp00wsl25x4fyushsg3med5g06fh3mangxkqgf3se4'
    },
    {
      note: 'https://github.com/bitcoin/bitcoin/blob/392dc68e37be9fc7adb32496b13d9b50262e317d/src/test/descriptor_tests.cpp#L454',
      expression:
        "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy",
      script: 'a91445a9a622a8b0a1269944be477640eedc447bbd8487'
    }
  ],
  invalid: [
    {
      note: 'This is a wif address, note however that KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik corresponds to mainnet',
      network: networks.testnet,
      expression:
        "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)",
      checksumRequired: false,
      //bdk-cli should throw here, but it does not :-/
      //bdk-cli -n testnet wallet -d "wpkh([de41e56d/84'/1'/0']KynD8ZKdViVo5W82oyxvE18BbG6nZPVQ8Td8hYbwU94RmyUALUik)" get_new_address
      address: 'tb1qkk7jt9nx3hf05tlxc80vzmvxvamdh6jsrk6y2z',
      throw: 'Invalid network version'
    },
    {
      note: 'it fails when not passing a checksum if required',
      network: networks.testnet,
      expression:
        "wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)",
      index: 23,
      checksumRequired: true,
      throw:
        "Error: descriptor wpkh([de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*) has not checksum"
    },
    {
      note: 'using a upub (which does not make sense using descriptors anymore; only xpub and tpub are supported)',
      network: networks.testnet,
      expression:
        "wpkh([de41e56d/84'/1'/0']upubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)",
      checksumRequired: false,
      index: 23,
      throw:
        "Error: Could not parse descriptor wpkh([de41e56d/84'/1'/0']upubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/0/*)"
    },
    {
      note: 'https://github.com/bitcoin/bitcoin/blob/392dc68e37be9fc7adb32496b13d9b50262e317d/src/test/descriptor_tests.cpp#L445',
      expression: 'sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)',
      checksumRequired: false
    },
    {
      note: 'https://github.com/bitcoin/bitcoin/blob/392dc68e37be9fc7adb32496b13d9b50262e317d/src/test/descriptor_tests.cpp#L447',
      expression: 'wsh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)',
      checksumRequired: false,
      throw: 'Error: Miniscript @0 is not sane'
    },
    {
      note: 'https://github.com/bitcoin/bitcoin/blob/392dc68e37be9fc7adb32496b13d9b50262e317d/src/test/descriptor_tests.cpp#L448',
      expression:
        'wsh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))',
      checksumRequired: false,
      throw: 'Error: Miniscript wpkh(@0) is not sane'
    },
    {
      note: 'https://github.com/bitcoin/bitcoin/blob/392dc68e37be9fc7adb32496b13d9b50262e317d/src/test/descriptor_tests.cpp#L449',
      expression:
        'wsh(sh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)))',
      checksumRequired: false,
      throw: 'Error: Miniscript sh(pk(@0)) is not sane'
    }
  ]
};
