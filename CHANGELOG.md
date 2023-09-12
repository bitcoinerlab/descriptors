# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Descriptor Buffer Comparison**:
  - Addressed a bug related to buffer comparisons in `src/descriptors.ts`.
    - Modified the comparison logic for `witnessScript` and `redeemScript` to handle cases where one of the buffers may be `undefined`.
    - Introduced the `eqBuffers` function to compare two buffers, ensuring that it correctly handles `undefined` values.
    - This fix ensures accurate and error-free descriptor comparisons, particularly crucial for finalizing psbt indexes.
    - Refer to [issue-20](https://github.com/bitcoinerlab/descriptors/issues/20) for more details.

## [1.1.1] - 2023-10-12

### Changed

- **React Native Compatibility**:
  - Adjusted the way the library imports `ledger-bitcoin` in `src/ledger.ts` to improve compatibility with React Native projects using the Metro bundler.
    - Previously, the library utilized dynamic imports (`await import('ledger-bitcoin')`), but this approach caused issues with Metro bundler. The bundler tried to unconditionally require `ledger-bitcoin` even if it wasn't installed (since it's an optional peerDependency).
    - The new approach bypasses this by using a direct `require` statement. For more details on the underlying issue, refer to [this React Native discussion](https://github.com/react-native-community/discussions-and-proposals/issues/120).
    - This update ensures smoother integration for developers using this library in React Native projects.

## [1.1.0] - 2023-10-7

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
