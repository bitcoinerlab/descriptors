# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2023-07-14

### Changed

- `ledger-bitcoin` is now a peer dependency. To use Ledger support, you need to install it separately. This change allows users to have control over the version of `ledger-bitcoin` they want to use and makes sure they are aware of the specific dependencies they are adding to their project. Additionally, if users are not interested in Ledger support, they can now omit `ledger-bitcoin` to minimize the size of their bundles.

### Removed

- `AppClient` is no longer exported within `@bitcoinerlab/descriptors`. `AppClient` is the client library used to connect and interact with Ledger devices. Now, you need to import it directly from `ledger-bitcoin`. This change provides more clarity and control over where the dependencies are coming from.
