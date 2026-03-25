'use strict';

const fs = require('fs');
const path = require('path');

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function assert(condition, message) {
  if (!condition) {
    console.error(`Publish check failed: ${message}`);
    process.exit(1);
  }
}

const root = readJson(path.resolve(__dirname, '..', 'package.json'));
const descriptors = readJson(
  path.resolve(__dirname, '..', 'packages', 'descriptors', 'package.json')
);
const scure = readJson(
  path.resolve(__dirname, '..', 'packages', 'descriptors-scure', 'package.json')
);

const version = root.version;

assert(
  descriptors.version === version,
  `@bitcoinerlab/descriptors version ${descriptors.version} must match core ${version}`
);
assert(
  scure.version === version,
  `@bitcoinerlab/descriptors-scure version ${scure.version} must match core ${version}`
);
assert(
  descriptors.engines?.node === root.engines?.node,
  `@bitcoinerlab/descriptors engines.node must match core (${root.engines?.node})`
);
assert(
  scure.engines?.node === root.engines?.node,
  `@bitcoinerlab/descriptors-scure engines.node must match core (${root.engines?.node})`
);

assert(
  descriptors.dependencies['@bitcoinerlab/descriptors-core'] === version,
  `@bitcoinerlab/descriptors must depend on @bitcoinerlab/descriptors-core exactly at ${version}`
);
assert(
  scure.dependencies['@bitcoinerlab/descriptors-core'] === version,
  `@bitcoinerlab/descriptors-scure must depend on @bitcoinerlab/descriptors-core exactly at ${version}`
);

for (const pkg of ['bitcoinjs-lib', 'bip32', 'ecpair']) {
  assert(
    descriptors.dependencies[pkg] === root.peerDependencies[pkg],
    `@bitcoinerlab/descriptors dependency ${pkg} must match core peer dependency ${root.peerDependencies[pkg]}`
  );
}

for (const pkg of [
  '@noble/curves',
  '@scure/base',
  '@scure/bip32',
  '@scure/btc-signer'
]) {
  assert(
    scure.dependencies[pkg] === root.peerDependencies[pkg],
    `@bitcoinerlab/descriptors-scure dependency ${pkg} must match core peer dependency ${root.peerDependencies[pkg]}`
  );
}

for (const pkg of [descriptors, scure]) {
  assert(
    pkg.peerDependencies['@ledgerhq/ledger-bitcoin'] ===
      root.peerDependencies['@ledgerhq/ledger-bitcoin'],
    `${pkg.name} optional Ledger peer must match core peer dependency ${root.peerDependencies['@ledgerhq/ledger-bitcoin']}`
  );
}

for (const pkg of [
  '@noble/curves',
  '@scure/base',
  '@scure/bip32',
  '@scure/btc-signer'
]) {
  assert(
    descriptors.dependencies[pkg] === undefined,
    `@bitcoinerlab/descriptors must not directly depend on ${pkg}`
  );
}

for (const pkg of [
  '@bitcoinerlab/secp256k1',
  'bitcoinjs-lib',
  'bip32',
  'ecpair'
]) {
  assert(
    scure.dependencies[pkg] === undefined,
    `@bitcoinerlab/descriptors-scure must not directly depend on ${pkg}`
  );
}

console.log(`Publish check OK for version ${version}`);
