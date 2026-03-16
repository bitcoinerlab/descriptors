// Jest config for running the test suite against the @scure/btc-signer adapter.
//
// Usage:  BITCOIN_LIB=scure npx jest --config jest.config.scure.js
//
// ESM-only packages (@scure/*, @noble/*) are transpiled to CJS by babel-jest
// so they work in jest's sandboxed VM runtime.

module.exports = {
  // Inherit from the project preset
  testPathIgnorePatterns: [
    'dist/',
    // This test specifically validates our reimplementation against
    // bitcoinjs-lib internals — not relevant for the scure adapter.
    'bitcoinjsLibInternals\\.test\\.js$'
  ],
  testMatch: ['**/*.test.js'],

  // Transform ESM-only packages to CJS via babel.
  // All transitive deps of @scure/btc-signer that use "type": "module":
  transformIgnorePatterns: [
    'node_modules/(?!(@scure|@noble|micro-packed)/)'
  ],
  transform: {
    '\\.js$': ['babel-jest', {
      presets: [
        ['@babel/preset-env', { targets: { node: 'current' } }]
      ]
    }]
  }
};
