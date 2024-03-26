# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2023-10-19

### Changed

- **Main Class Renaming**:
  - Deprecated the old naming convention.
  - Renamed the main class from "Descriptor" to "Output".
  - This change emphasizes that a descriptor describes an "Output".

- **Parameter Refactoring**:
  - Refactored the main input parameter in the constructor of the "Output" class.
    - Previously: "expression" (string).
    - Now: "descriptor" (string).
  - This modification better aligns with the principle above that a descriptor describes an Output.

- **Function Updates**:
  - All functions that utilized "expression" have been updated to use "descriptor".

- **Ledger Hardware Wallet & PSBT Finalizers Improvements**:
  - Refined functions related to the Ledger Hardware Wallet and PSBT finalizers.
  - These refinements greatly simplify and enhance the library's usability. See details below.

- **Finalizers Update**:
  - Deprecated `updatePsbt` in favor of `updatePsbtAsInput`.
    - The new function returns the finalizer directly instead of the input number.
    - This change eliminates the need to explicitly call the `finalizePsbtInput` method of the Output class.
    - Previous implementations were error-prone due to the need to keep track of the input number of the PSBT input being finalized and the Output instance of the previous output.

- **Ledger Enhancements**:
  - Simplified the signer's requirements before v2.0.0, which previously required tracking the Output instances of each input and passing them to the signer.
    - The essential information is now directly extracted from the PSBT, facilitating usability.
  - Unified `ledgerClient` and `ledgerState` parameters into a new type `LedgerManager`, which also includes an instance to the Elliptic Curve Library (`ecc`).
    - To initialize: `const ledgerManager = {ledgerClient, ledgerState: {}, ecc};`, where `import * as ecc from '@bitcoinerlab/secp256k1'`.

- **Deprecation Notices**:
  - While the old functions and classes with former signatures remain available in 2.0.0, they are now deprecated.
    - Transitioning to v2.0.0 requires no immediate action, but you may encounter "deprecated" warnings if your code editor supports typedoc/jsdoc linting.
    - It's highly recommended to start updating to the new functions and classes.

- **Key Updates to Consider**:
  - Substitute `new Descriptor({expression})` with `new Output({descriptor})`.
  - Transition from `expand({expression})` to `expand({descriptor})`.
  - Use `updatePsbtAsInput` as `updatePsbt` is now deprecated.
  - Introduced `updatePsbtAsOutput` for completeness.
  - Opt for finalizers returned by `updatePsbtAsInput` as `finalizePsbtInput` and `finalizePsbt` have been deprecated.

- **Additional Ledger Updates**:
  - Functions previously expecting `ledgerClient` and `ledgerState` should now receive `ledgerManager` instead.
    - This change affects multiple functions, including `signLedger`, all Ledger script expression functions and also: `keyExpressionLedger`, `registerLedgerWallet`, `getLedgerMasterFingerPrint`, and `assertLedgerApp`.
  - `signLedger` and `signInputLedger` no longer necessitate passing an instance to the former `Descriptor` class. All relevant information is automatically retrieved from the psbt now.

- **Testing Enhancements**:
  - **Deprecated Function Testing**:
    - Retained old tests, now suffixed with `-deprecated`, to continue testing the deprecated functions and classes.
  - **New API Testing**:
    - Introduced additional tests specifically designed to evaluate the new API's functionality.

- **Documentation Enhancements**:
  - Extensively documented all methods using typedoc.
    - This facilitates the generation of a comprehensive API reference for developers.
  - Updated the README.md to mirror the latest changes, optimizing clarity by referencing the API for intricate details.

### Fixed

- **Descriptor Buffer Comparison**:
  - Resolved a bug associated with buffer comparisons in `src/descriptors.ts`.
    - Adjusted the comparison logic for `witnessScript` and `redeemScript` to manage scenarios where one buffer may be `undefined`.
    - Introduced the `eqBuffers` function for accurate buffer comparisons, particularly when handling `undefined` values.
    - This correction is vital for precise descriptor comparisons, especially when determining psbt indexes.
  - For an in-depth analysis, consult [issue-20](https://github.com/bitcoinerlab/descriptors/issues/20).

## [1.1.1] - 2023-9-12

### Changed

- **React Native Compatibility**:
  - Adjusted the way the library imports `ledger-bitcoin` in `src/ledger.ts` to improve compatibility with React Native projects using the Metro bundler.
    - Previously, the library utilized dynamic imports (`await import('ledger-bitcoin')`), but this approach caused issues with Metro bundler. The bundler tried to unconditionally require `ledger-bitcoin` even if it wasn't installed (since it's an optional peerDependency).
    - The new approach bypasses this by using a direct `require` statement. For more details on the underlying issue, refer to [this React Native discussion](https://github.com/react-native-community/discussions-and-proposals/issues/120).
    - This update ensures smoother integration for developers using this library in React Native projects.

## [1.1.0] - 2023-9-7

### Changed

- **Configuration**:
  - Adopted sharable configurations from `@bitcoinerlab/configs` to enhance library maintainability.

- **Exported Types**:
  - Revised the exported types for descriptors:
    - **Before**: The library previously exported both `DescriptorInterface` and `DescriptorInterfaceConstructor`.
    - **Now**: The library now exports `DescriptorInstance`, a more comprehensive type derived using `InstanceType<ReturnType<typeof DescriptorsFactory>['Descriptor']>;`. This type embodies an instance of the descriptor class returned by the factory, inclusive of its methods. Furthermore, the library now exports `DescriptorConstructor` in place of `DescriptorInterfaceConstructor`.

      If you previously used `DescriptorInterface` for type annotations with instances of the descriptor class, it's recommended to transition to the newly introduced `DescriptorInstance` type. For example: `const descriptor: DescriptorInterface = new Descriptor();` should now be `const descriptor: DescriptorInstance = new Descriptor();`. This new type not only offers more precise typings but also has a more appropriate name.

## [1.0.1] - 2023-07-14

### Changed
- Updated `@bitcoinerlab/secp256k1` from version `1.0.2` to `1.0.5`, `bip32` from `3.1.0` to `4.0.0`, and `bitcoinjs-lib` from `6.1.0` to `6.1.3`. There are no breaking changes.
- Started using `noble-hashes` instead of `create-hash`, `pbkdf2`, and `randombytes`. This change was made to improve the maintainability of the library.

## [1.0.0] - 2023-07-14

### Changed

- `ledger-bitcoin` is now a peer dependency. To use Ledger support, you need to install it separately. This change allows users to have control over the version of `ledger-bitcoin` they want to use and makes sure they are aware of the specific dependencies they are adding to their project. Additionally, if users are not interested in Ledger support, they can now omit `ledger-bitcoin` to minimize the size of their bundles.

### Removed

- `AppClient` is no longer exported within `@bitcoinerlab/descriptors`. `AppClient` is the client library used to connect and interact with Ledger devices. Now, you need to import it directly from `ledger-bitcoin`. This change provides more clarity and control over where the dependencies are coming from.
