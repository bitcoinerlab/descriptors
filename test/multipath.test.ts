// Copyright (c) 2026 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import { networks } from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory } from '../dist';

const { Output } = DescriptorsFactory(ecc);

const XPUB_ROOT =
  "[de41e56d/84'/1'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra";

describe('Descriptor multipath key expressions', () => {
  test('resolves /<0;1>/* using change and index', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<0;1>/*)`;
    const descriptorReceive = `wpkh(${XPUB_ROOT}/0/*)`;
    const descriptorChange = `wpkh(${XPUB_ROOT}/1/*)`;

    const receiveAddress = new Output({
      descriptor: descriptorMulti,
      network: networks.testnet,
      change: 0,
      index: 23
    }).getAddress();

    const receiveReferenceAddress = new Output({
      descriptor: descriptorReceive,
      network: networks.testnet,
      index: 23
    }).getAddress();

    const changeAddress = new Output({
      descriptor: descriptorMulti,
      network: networks.testnet,
      change: 1,
      index: 23
    }).getAddress();

    const changeReferenceAddress = new Output({
      descriptor: descriptorChange,
      network: networks.testnet,
      index: 23
    }).getAddress();

    expect(receiveAddress).toEqual(receiveReferenceAddress);
    expect(changeAddress).toEqual(changeReferenceAddress);
  });

  test('supports /** shorthand', () => {
    const descriptorShorthand = `wpkh(${XPUB_ROOT}/**)`;
    const descriptorReference = `wpkh(${XPUB_ROOT}/1/*)`;

    const shorthandAddress = new Output({
      descriptor: descriptorShorthand,
      network: networks.testnet,
      change: 1,
      index: 23
    }).getAddress();

    const referenceAddress = new Output({
      descriptor: descriptorReference,
      network: networks.testnet,
      index: 23
    }).getAddress();

    expect(shorthandAddress).toEqual(referenceAddress);
  });

  test('supports tuple values beyond 0/1 and selects by value', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<2;3;5>/*)`;
    const descriptorReference = `wpkh(${XPUB_ROOT}/5/*)`;

    const multiAddress = new Output({
      descriptor: descriptorMulti,
      network: networks.testnet,
      change: 5,
      index: 23
    }).getAddress();

    const referenceAddress = new Output({
      descriptor: descriptorReference,
      network: networks.testnet,
      index: 23
    }).getAddress();

    expect(multiAddress).toEqual(referenceAddress);
  });

  test('throws when change is missing for multipath descriptor', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<0;1>/*)`;

    expect(
      () =>
        new Output({
          descriptor: descriptorMulti,
          network: networks.testnet,
          index: 23
        })
    ).toThrow('Error: change was not provided for multipath descriptor');
  });

  test('throws when tuple values are not strictly increasing', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<1;0>/*)`;

    expect(
      () =>
        new Output({
          descriptor: descriptorMulti,
          network: networks.testnet,
          change: 0,
          index: 23
        })
    ).toThrow(
      'Error: multipath tuple values must be strictly increasing from left to right'
    );
  });

  test('throws when tuple values are not strictly increasing (duplicate)', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<0;0>/*)`;

    expect(
      () =>
        new Output({
          descriptor: descriptorMulti,
          network: networks.testnet,
          change: 0,
          index: 23
        })
    ).toThrow(
      'Error: multipath tuple values must be strictly increasing from left to right'
    );
  });

  test('throws when tuple contains non-decimal values', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<0;1h>/*)`;

    expect(
      () =>
        new Output({
          descriptor: descriptorMulti,
          network: networks.testnet,
          change: 0,
          index: 23
        })
    ).toThrow('Error: multipath tuple values must be decimal numbers');
  });

  test('throws when change value is not present in tuple', () => {
    const descriptorMulti = `wpkh(${XPUB_ROOT}/<0;1;2>/*)`;

    expect(
      () =>
        new Output({
          descriptor: descriptorMulti,
          network: networks.testnet,
          change: 9,
          index: 23
        })
    ).toThrow('Error: change 9 not found in multipath tuple <0;1;2>');
  });
});
