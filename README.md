# Bitcoin Descriptors Library

This library is designed to parse and create Bitcoin Descriptors, including Miniscript, and generate Partially Signed Bitcoin Transactions (PSBTs). It also provides PSBT finalizers and signers for single-signature, BIP32, and Hardware Wallets.

## Features

- Parses and creates Bitcoin Descriptors (including those based on the Miniscript language).
- Generates Partially Signed Bitcoin Transactions (PSBTs).
- Provides PSBT finalizers and signers for single-signature, BIP32, and Hardware Wallets (currently supports Ledger devices; more devices are planned).

## Concepts

Before we dive into the Bitcoin Descriptors Library, let's briefly explain some key concepts related to Bitcoin descriptors and partially signed Bitcoin transactions (PSBTs).

### Descriptors

In Bitcoin, a transaction consists of a set of inputs that are spent into a different set of outputs. Each input spends an output in a previous transaction. A Bitcoin descriptor is a string of text that describes the rules and conditions required to spend an output in a transaction.

For example, `wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)` is a descriptor that describes a pay-to-witness-public-key-hash (P2WPKH) type of output with the specified public key. If you know the corresponding private key for the transaction for which this descriptor is an output, you can spend it.

Descriptors can express much more complex conditions, such as multi-party cooperation, time-locked outputs, and more. These conditions can be expressed using the Bitcoin Miniscript language, which is a way of writing Bitcoin Scripts in a structured and more easily understandable way.

### Partially Signed Bitcoin Transactions (PSBTs)

A PSBT (Partially Signed Bitcoin Transaction) is a format for sharing Bitcoin transactions between different parties.

PSBTs come in handy when working with descriptors, especially when using scripts, because they allow multiple parties to collaborate in the signing process. This is especially useful when using hardware wallets or other devices that require separate signatures or authorizations.

This library is able to generate addresses and scriptPubKeys from descriptors, which can be used to receive funds from others, and it is also able to sign and spend unspent outputs described by those same descriptors.

## Usage

To use this library (and accompanying libraries), you can install them using:

```
npm install @bitcoinerlab/descriptors
npm install @bitcoinerlab/miniscript
npm install @bitcoinerlab/secp256k1
```

The library can be split into four main parts:

- The `Descriptor` class, which is the core component that parses descriptors and can be used to finalize partially signed Bitcoin transactions (PSBTs).
- `keyExpressions` and `scriptExpressions`, which provide functions to create descriptor and key expressions (strings) from structured data, making it easier to work with complex descriptors.
- PSBT signers and finalizers, which are used to manage the signing and finalization of PSBTs.
- Hardware wallet integration, which provides support for interacting with hardware wallets such as Ledger devices.

### Descriptor class

The Descriptor class is created dynamically by providing a cryptographic secp256k1 engine as shown below:

```javascript
import * as secp256k1 from '@bitcoinerlab/secp256k1';
import * as descriptors from '@bitcoinerlab/descriptors';
const { Descriptor } = descriptors.DescriptorsFactory(secp256k1);
```

After that, you can obtain an instance for a descriptor expression, such as a wpkh expression, like this:

```javascript
const wpkhDescriptor = new Descriptor({
  expression:
    'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
});
```

Refer to the [documentation](#documentation), [guides](https://bitcoinerlab.com/guides) and [integration tests](https://github.com/bitcoinerlab/descriptors/tree/main/test/integration) for more information on the other options for creating a new `Descriptor`.

The Descriptor class provides several useful methods such as `getAddress()`, `getScriptPubKey()`, `updatePsbt()`, `finalizePsbt()` or `expand()`, which decomposes a descriptor into its elemental parts. These methods can be used to extract information from the descriptor for further processing. For more information about these and other methods, please refer to the [documentation](#documentation).

The `updatePsbt()` method is a crucial part of the library that adds an input to the PSBT corresponding to the UTXO (unspent transaction output) described by the descriptor. Additionally, when the descriptor expresses an absolute time-spending condition, such as "This UTXO can only be spent after block N," `updatePsbt()` adds timelock information to the PSBT.

To call `updatePsbt()`, use the following syntax:

```javascript
const inputIndex = descriptor.updatePsbt({ psbt, txHex, vout });
```

Here, `psbt` is an instance of a [bitconjs-lib Psbt class](https://github.com/bitcoinjs/bitcoinjs-lib), `txHex` is the hex string that serializes the previous transaction, and `vout` is an integer corresponding to the output index of the descriptor in the previous transaction. The method returns a number that corresponds to the input number that this descriptor will take in the `psbt`.

The `finalizePsbt()` method is used to add the unlocking script (scriptWitness or scriptSig) that satisfies the spending condition to the transaction, effectively finalizing the Psbt. This method is called with the following syntax:

```javascript
descriptor.finalizePsbt({ index, psbt });
```

Here, index is the inputIndex obtained from the updatePsbt() method and psbt is an instance of a bitcoinjs-lib Psbt object.

### keyExpressions and scriptExpressions

This library includes a set of function helpers that facilitate the generation of the `expression` parameter in the constructor of the `Descriptor` class. These helpers are located under the `scriptExpressions` module, which can be imported using the following statement:

```javascript
import { scriptExpressions } from '@bitcoinerlab/descriptors';
```

`scriptExpressions` includes functions that generate script expressions for commonly used script expressions. Some of the available functions are `pkhLedger()`, `shWpkhLedger`, `wpkhLedger`, `pkhLedger()`, `shWpkhLedger` and `wpkhLedger`.

When using BIP32-based descriptors, the following parameters are required for the `scriptExpressions` functions:

```javascript
{
  masterNode: BIP32Interface; //A bitcoinjs-lib instance of a BIP32 object.
  network?: Network; //A bitcoinjs-lib network
  account: number;
  change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string; //You can use change & index or a keyPath such as "/0/0"
  isPublic?: boolean; //Whether to use xpub or xprv
}
```

For Ledger, `ledgerClient` and `ledgerState` are used instead of `masterNode`. These will be explained later when we discuss Ledger integration.

The `keyExpressions` category includes functions that generate string representations of key expressions for public keys. This is useful when working with miniscript-based descriptors.

This library includes the following `keyExpressions`: `keyExpressionBIP32` and `keyExpressionLedger`. They can be imported as follows:

```javascript
import { keyExpressionBIP32, keyExpressionLedger } from '@bitcoinerlab/descriptors';
```

The parameters required for these functions are:

```javascript
function keyExpressionBIP32({
  masterNode: BIP32Interface;
  originPath: string;
  change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string | undefined; //In the case of the Ledger, keyPath must be /<1;0>/number
  isPublic?: boolean;
});
```
For Ledger, `ledgerClient` and `ledgerState` are used instead of `masterNode`.

Both functions will generate strings that fully define BIP32 keys. For example: `[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*`. Read [Bitcoin Core descriptors documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) to learn more about Key Expressions.

### Signers and Finalizers

This library provides a Psbt finalizer and three types of signers: ECPair for single-signature, BIP32, and Ledger (for Ledger Wallet devices, with plans for other devices).

To use them, import them as follows:

```javascript
import { signers, finalizePsbt } from '@bitcoinerlab/descriptors';
```

To sign with the signers:

```javascript
await signers.signLedger({
  ledgerClient,
  ledgerState,
  psbt,
  descriptors: psbtInputDescriptors
});
//Here psbtInputDescriptors is an array of descriptors odered by their respective inputIndex in the psbt
signers.signBIP32({ psbt, masterNode });
signers.signECPair({ psbt, ecpair }); //Where ecpair is an instance of bitcoinjs-lib ECPairInterface
```

To finalize the `psbt`, you can either call the method `finalizePsbtInput({ index, psbt })` on each descriptor, passing as arguments the `psbt` and its input `index`, or call the helper function: `finalizePsbt({psbt, descriptors })`. In the latter case, `descriptors` is an array of descriptors ordered by their respective input index in the `psbt`.

### Hardware Wallet Integration

This library currently provides integration with Ledger wallets. Support for more devices is planned.

To use a Ledger device for signing, you can import the necessary functions as follows:

```javascript
import { ledger } from '@bitcoinerlab/descriptors';
```

You can then use the following code to assert that the Ledger app is running Bitcoin Test version 2.1.0 or higher, and to create a new Ledger client:

```javascript
//Throws if not running Bitcoin Test >= 2.1.0
await descriptors.ledger.assertLedgerApp({
  transport,
  name: 'Bitcoin Test',
  minVersion: '2.1.0'
});

const ledgerClient = new descriptors.ledger.AppClient(transport);
```
Here, `transport` is an instance of a Transport object that allows communication with Ledger devices. You can use any of the transports [provided by Ledger](https://github.com/LedgerHQ/ledger-live#libs---libraries).

To register the policies of non-standard descriptors on the Ledger device, you can use the following code:

```javascript
await descriptors.ledger.registerLedgerWallet({
  ledgerClient,
  ledgerState,
  descriptor: wshDescriptor,
  policyName: 'BitcoinerLab'
});
```
This code will auto-skip the registration policy if it already exists. Please refer to [Ledger documentation](https://github.com/LedgerHQ/app-bitcoin-new/blob/develop/doc/wallet.md) to learn more about their Wallet Policies registration procedures.

Finally, `ledgerState` is an object used to store information related to Ledger devices. Although Ledger devices themselves are stateless, this object can be used to store information such as xpubs, master fingerprints, and wallet policies. You can pass an initially empty object that will be updated with more information as it is used. The object can be serialized and stored.

## Documentation

To generate the API documentation for this package, follow these steps:

```
git clone https://github.com/bitcoinerlab/descriptors
cd descriptors/
npm run docs
```
This will generate the API documentation in the docs/ directory. Open the index.html file located in the docs/ directory to view the documentation.

Please note that not all the functions have been fully documented yet. However, you can easily understand their usage by reading the source code or by checking the integration tests or playgrounds.

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
