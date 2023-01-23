// Converted to Javascript by Jose-Luis Landabaso, 2023 - https://bitcoinerlab.com
// Source: https://github.com/bitcoin/bitcoin/blob/master/src/script/descriptor.cpp
// Distributed under the MIT software license
const PolyMod = (c, val) => {
  let c0 = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ val;
  if (c0 & 1n) c ^= 0xf5dee51989n;
  if (c0 & 2n) c ^= 0xa9fdca3312n;
  if (c0 & 4n) c ^= 0x1bab10e32dn;
  if (c0 & 8n) c ^= 0x3706b1677an;
  if (c0 & 16n) c ^= 0x644d626ffdn;
  return c;
};

export const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
export const DescriptorChecksum = span => {
  const INPUT_CHARSET =
    '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';

  let c = 1n;
  let cls = 0n;
  let clscount = 0n;
  for (let ch of span) {
    let pos = BigInt(INPUT_CHARSET.indexOf(ch));
    if (pos === -1n) return '';
    c = PolyMod(c, pos & 31n);
    cls = cls * 3n + (pos >> 5n);
    if (++clscount === 3n) {
      c = PolyMod(c, cls);
      cls = 0n;
      clscount = 0n;
    }
  }
  if (clscount > 0n) c = PolyMod(c, cls);
  for (let j = 0; j < 8; ++j) c = PolyMod(c, 0n);
  c ^= 1n;

  let ret = '';
  for (let j = 0; j < 8; ++j)
    ret += CHECKSUM_CHARSET[(c >> (5n * (7n - BigInt(j)))) & 31n];
  return ret;
};
