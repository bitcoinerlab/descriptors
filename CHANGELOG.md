# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2023-10-7

### Changed

- **Configuration**:
  - Adopted sharable configs from `@bitcoinerlab/configs` to improve the maintainability of the library.

- **Exported Types**:
  - Changed the exported type for descriptors:
    - **Before**: The library exported `DescriptorInterfaceConstructor` which was primarily used for typing the methods of a descriptor instance but not its constructor.
    - **Now**: The library exports `Descriptor`, a more comprehensive type derived using `InstanceType<ReturnType<typeof DescriptorsFactory>['Descriptor']>;`. This type represents an instance of the descriptor class returned by the factory, including its methods.

      If you had previously relied on `DescriptorInterface` for typing instances of the descriptor class, please update your implementations to use the new `Descriptor` type. The new type offers more accurate typings and includes methods as well as properties of descriptor instances.

## [1.0.1] - 2023-07-14

### Changed
- Updated `@bitcoinerlab/secp256k1` from version `1.0.2` to `1.0.5`, `bip32` from `3.1.0` to `4.0.0`, and `bitcoinjs-lib` from `6.1.0` to `6.1.3`. There are no breaking changes.
- Started using `noble-hashes` instead of `create-hash`, `pbkdf2`, and `randombytes`. This change was made to improve the maintainability of the library.

## [1.0.0] - 2023-07-14

### Changed

- `ledger-bitcoin` is now a peer dependency. To use Ledger support, you need to install it separately. This change allows users to have control over the version of `ledger-bitcoin` they want to use and makes sure they are aware of the specific dependencies they are adding to their project. Additionally, if users are not interested in Ledger support, they can now omit `ledger-bitcoin` to minimize the size of their bundles.

### Removed

- `AppClient` is no longer exported within `@bitcoinerlab/descriptors`. `AppClient` is the client library used to connect and interact with Ledger devices. Now, you need to import it directly from `ledger-bitcoin`. This change provides more clarity and control over where the dependencies are coming from.
