// Used together with the Jest config in package.json:
//
//   "jest": {
//     "preset": "@bitcoinerlab/configs",
//     "transform": {
//       "^.+node_modules/(?:@noble|@scure|micro-packed)/.+\\.js$": "<rootDir>/jest-esm-transform.cjs"
//     },
//     "transformIgnorePatterns": [
//       "/node_modules/(?!(@bitcoinerlab/secp256k1|@noble|@scure|micro-packed)/)"
//     ]
//   }
//
// Jest normally skips transforming node_modules and cannot execute these
// ESM-only dependencies when they are required from the compiled CommonJS dist
// output. The secp256k1 parent path is allowlisted so Jest can reach its nested
// Noble modules. This transformer rewrites the matched ESM packages to CommonJS
// for the test runtime.

const ts = require('typescript');

module.exports = {
  process(src, filename) {
    const { outputText } = ts.transpileModule(src, {
      fileName: filename,
      compilerOptions: {
        allowJs: true,
        esModuleInterop: true,
        module: ts.ModuleKind.CommonJS,
        sourceMap: false,
        target: ts.ScriptTarget.ES2021
      }
    });
    return { code: outputText };
  }
};
