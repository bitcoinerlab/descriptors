## Bitcoin Descriptors Library *Pre Release*

This library is designed to parse and create Bitcoin Descriptors, including Miniscript, and generate Partially Signed Bitcoin Transactions (PSBTs). It also provides PSBT finalizers and signers for single-signature, BIP32, and Hardware Wallets.

**NOTE: This is a pre-release version only.** The Usage documentation is still being finalized. However, you can take a look at the [integration tests](https://github.com/bitcoinerlab/descriptors/tree/main/test/integration) for some examples of how to use this library.

### Features

- Parses and creates Bitcoin Descriptors (including those based on the Miniscript language).
- Generates Partially Signed Bitcoin Transactions (PSBTs).
- Provides PSBT finalizers and signers for single-signature, BIP32, and Hardware Wallets (currently supports Ledger devices; more devices are planned).

### Usage

Usage instructions will be added to this README as soon as they are finalized. In the meantime, please refer to the [integration tests](https://github.com/bitcoinerlab/descriptors/tree/main/test/integration) for some examples of how to use this library.

## Authors and Contributors

The project was initially developed and is currently maintained by [Jose-Luis Landabaso](https://github.com/landabaso). Contributions and help from other developers are welcome.

Here are some resources to help you get started with contributing:

### Building from source

To download the source code and build the project, follow these steps:

1. Clone the repository:

```
git clone https://github.com/bitcoinerlab/descriptors.git
```

2. Install the dependencies:

```
npm install
```

3. Build the project:

```
npm run build
```

This will build the project and generate the necessary files in the `dist` directory.

### Testing


Before committing any code, make sure it passes all tests. First, make sure that you have a Bitcoin regtest node running and that you have set up the Express-based bitcoind manager from this repository: https://github.com/bitcoinjs/regtest-server. The manager should be running on 127.0.0.1:8080.

The easiest way to set up these services is to use a Docker image that comes preconfigured with them. You can use the following commands to download and run the Docker image:

```bash
docker pull junderw/bitcoinjs-regtest-server
docker run -d -p 127.0.0.1:8080:8080 junderw/bitcoinjs-regtest-server
```

This will start a container running a Bitcoin regtest node and the bitcoind manager on your machine. Once you have your node and manager set up, you can run the tests using the following command:

```
npm run test
```

And, in case you have a Ledger device:

```
npm run test:integration:ledger
```

### License

This project is licensed under the MIT License.

