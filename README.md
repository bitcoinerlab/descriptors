# Bitcoin Descriptors Library

This library is designed to parse and create Bitcoin Descriptors, including Miniscript, and generate Partially Signed Bitcoin Transactions (PSBTs). It also provides PSBT signers and finalizers for single-signature, BIP32, and Hardware Wallets.

## Features

- Parses and creates [Bitcoin Descriptors](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) (including those based on the [Miniscript language](https://bitcoinerlab.com/modules/miniscript)).
- Generates Partially Signed Bitcoin Transactions (PSBTs).
- Provides PSBT finalizers and signers for single-signature, BIP32, and Hardware Wallets (currently supports Ledger devices; more devices are planned).

## Concepts

This library has two main capabilities related to Bitcoin descriptors. Firstly, it can generate `addresses` and `scriptPubKeys` from descriptors. These `addresses` and `scriptPubKeys` can be used to receive funds from other parties. Secondly, the library is able to sign transactions and spend unspent outputs described by those same descriptors. In order to do this, the descriptors must first be set into a PSBT.

If you are not familiar with _Bitcoin descriptors_ and _partially signed Bitcoin transactions (PSBTs)_, click on the section below to expand and read more about these concepts.

<details>
  <summary>Concepts</summary>

### Descriptors

In Bitcoin, a transaction consists of a set of inputs that are spent into a different set of outputs. Each input spends an output in a previous transaction. A Bitcoin descriptor is a string of text that describes the rules and conditions required to spend an output in a transaction.

For example, `wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)` is a descriptor that describes a pay-to-witness-public-key-hash (P2WPKH) type of output with the specified public key. If you know the corresponding private key for the transaction for which this descriptor is an output, you can spend it.

Descriptors can express much more complex conditions, such as multi-party cooperation, time-locked outputs, and more. These conditions can be expressed using the Bitcoin Miniscript language, which is a way of writing Bitcoin Scripts in a structured and more easily understandable way.

### Partially Signed Bitcoin Transactions (PSBTs)

A PSBT (Partially Signed Bitcoin Transaction) is a format for sharing Bitcoin transactions between different parties.

PSBTs come in handy when working with descriptors, especially when using scripts, because they allow multiple parties to collaborate in the signing process. This is especially useful when using hardware wallets or other devices that require separate signatures or authorizations.

</details>

## Usage

Before we dive in, it's worth mentioning that we have several comprehensive guides available covering different aspects of the library. These guides provide explanations and code examples in interactive playgrounds, allowing you to see the changes in the output as you modify the code. This hands-on learning experience, combined with clear explanations, helps you better understand how to use the library effectively. [Check out the available guides here](https://bitcoinerlab.com/guides).

To use this library (and accompanying libraries), you can install them using:

```bash
npm install @bitcoinerlab/descriptors
npm install @bitcoinerlab/miniscript
npm install @bitcoinerlab/secp256k1
```

The library can be split into four main parts:

- The `Output` class is the central component for managing descriptors. It facilitates the creation of outputs to receive funds and enables the signing and finalization of PSBTs (Partially Signed Bitcoin Transactions) for spending UTXOs (Unspent Transaction Outputs).
- `keyExpressions` and `scriptExpressions`, which provide functions to create key and descriptor expressions (strings) from structured data, making it easier to work with complex descriptors.
- PSBT signers and finalizers, which are used to manage the signing and finalization of PSBTs.
- Hardware wallet integration, which provides support for interacting with hardware wallets such as Ledger devices.

### Output class

The `Output` class is dynamically created by providing a cryptographic secp256k1 engine as shown below:

```javascript
import * as ecc from '@bitcoinerlab/secp256k1';
import * as descriptors from '@bitcoinerlab/descriptors';
const { Output } = descriptors.DescriptorsFactory(ecc);
```

Once set up, you can obtain an instance for an output, described by a descriptor such as a `wpkh`, as follows:

```javascript
const wpkhOutput = new Output({
  descriptor:
    'wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)'
});
```

Here are the parameters that can be used to create an `Output`:

```javascript
constructor({
  descriptor, // The descriptor string in ASCII format. It may include a "*"
              // to denote an arbitrary index (aka ranged descriptors).
  index,      // The descriptor's index in the case of a range descriptor
              // (must be an integer >= 0).
  checksumRequired = false // Optional flag indicating if the descriptor is
                           // required to include a checksum. Defaults to false.
  allowMiniscriptInP2SH = false, // Flag indicating if this instance can parse
                                 // and generate script satisfactions for
                                 // sh(miniscript) top-level expressions of
                                 // miniscripts. This is not recommended.
  network = networks.bitcoin, // One of bitcoinjs-lib `networks`
                              // (https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/networks.js)
                              // or another one with the same interface.
  preimages = [], // An array of preimages of type `Preimage`: `Preimage[]`.
                  // This info is necessary to finalize Psbts.
  signersPubKeys // (Optional): An array of the public keys used for signing
                 // the transaction when spending the output associated with
                 // this descriptor. This parameter is only used if the
                 // descriptor object is being used to finalize a transaction.
                 // It is necessary to specify the spending path when working
                 // with miniscript-based expressions that have multiple
                 // spending paths. Set this parameter to an array containing
                 // the public keys involved in the desired spending path.
                 // Leave it `undefined` if you only need to generate the
                 // `scriptPubKey` or `address` for a descriptor, or if all
                 // the public keys involved in the descriptor will sign the
                 // transaction. In the latter case, the satisfier will
                 // automatically choose the most optimal spending path in terms
                 // of tx size (if more than one path is available).
                 // For more details on using this parameter, refer to this
                 // Stack Exchange answer: https://bitcoin.stackexchange.com/a/118036/89665
});
```

The `Output` class offers various helpful methods, including `getAddress()`, which returns the address associated with the descriptor, `getScriptPubKey()`, which returns the `scriptPubKey` for the descriptor, `expand()`, which decomposes a descriptor into its elemental parts, `updatePsbtAsInput()`, `updatePsbtAsOutput()` and `finalizePsbtInput()`.

The `updatePsbtAsInput()` method is an essential part of the library, responsible for adding an input to the PSBT corresponding to the UTXO  described by the descriptor. Additionally, when the descriptor expresses an absolute time-spending condition, such as "This UTXO can only be spent after block N," `updatePsbtAsInput()` adds timelock information to the PSBT.

To call `updatePsbtAsInput()`, use the following syntax:

```javascript
const inputIndex = output.updatePsbtAsInput({ psbt, txHex, vout });
```

Here, `psbt` refers to the [bitcoinjs-lib Psbt class](https://github.com/bitcoinjs/bitcoinjs-lib). The parameter `txHex` denotes a hex string that serializes the previous transaction containing this output. Meanwhile, `vout` is an integer that marks the position of the output within that transaction. The method returns a number that indicates the position this output will hold when utilized as input in the current `psbt` transaction.

Conversely, `updatePsbtAsOutput` allows you to add an output to a PSBT. For instance, to configure a `psbt` that sends `10,000` sats to the SegWit address `bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x`:

```javascript
const recipientOutput = 
 new Output({ descriptor: `addr(bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x)` });
recipientOutput.updatePsbtAsOutput({ psbt, value: 10000 });
```

The `finalizePsbtInput()` method completes a PSBT input by adding the unlocking script (`scriptWitness` or `scriptSig`) that satisfies the output's spending conditions. Bear in mind that both `scriptSig` and `scriptWitness` incorporate signatures. As such, you should complete all necessary signing operations before calling this method. Detailed [explanations on the `finalizePsbtInput` method](#signers-and-finalizers-finalize-psbt-input) can be found in the Signers and Finalizers section.

For further information on using the `Output` class, refer to the [comprehensive guides](https://bitcoinerlab.com/guides) that offer explanations and playgrounds to help learn the module. Additionally, a [Stack Exchange answer](https://bitcoin.stackexchange.com/a/118036/89665) provides a focused explanation on the constructor, specifically the `signersPubKeys` parameter, and the usage of `updatePsbtAsInput`, `finalizePsbtInput`, `getAddress`, and `getScriptPubKey`.

#### Tip: Parsing descriptors without instantiating a class

`DescriptorsFactory` provides a convenient `expand()` function that allows you to parse a descriptor without the need to instantiate the `Output` class. This function can be used as follows:

```javascript
const { expand } = descriptors.DescriptorsFactory(ecc);
const result = expand({
  descriptor: 'sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))',
  network: networks.testnet, // One of bitcoinjs-lib `networks`
                             // (https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/networks.js)
                             // or another one with the same interface.
                             // Optional (defaults to bitcoin mainnet). 
  allowMiniscriptInP2SH: true, // Optional flag to allow miniscript in P2SH.
                              // Defaults to false.
  index, // Optional. The descriptor's index in the case of a range descriptor
         // (must be an integer >= 0). If not set for ranged descriptors, then 
         // the function will return an expansionMap with ranged keyPaths and
         // won't compute Payment or scripts.
  checksumRequired = false // Optional flag indicating if the descriptor is
                           // required to include a checksum. Defaults to false.
});
```

The `expand()` function returns an object with the following properties:

- `payment: Payment | undefined`: The corresponding [bitcoinjs-lib Payment](https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/ts_src/payments/index.ts) for the provided descriptor, if applicable.
- `expandedExpression: string | undefined`: The expanded descriptor expression.
- `miniscript: string | undefined`: The extracted miniscript from the descriptor, if any.
- `expansionMap: ExpansionMap | undefined`: A map of key expressions in the descriptor to their corresponding expanded keys.
- `isSegwit: boolean | undefined`: A boolean indicating whether the descriptor represents a SegWit script.
- `expandedMiniscript: string | undefined`: The expanded miniscript, if any.
- `redeemScript: Buffer | undefined`: The redeem script for the descriptor, if applicable.
- `witnessScript: Buffer | undefined`: The witness script for the descriptor, if applicable.
- `isRanged: boolean` : Whether the descriptor describes a range of outputs (using wildcards `*`).
- `canonicalExpression` : This is the preferred or authoritative representation of the descriptor. It standardizes the descriptor by replacing indexes on wildcards and eliminating checksums.

For the example descriptor provided, the `expandedExpression` and a portion of the `expansionMap` would be as follows:

```javascript
// descriptor: 'sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))'

expandedExpression: 'sh(wsh(andor(pk(@0),older(8640),pk(@1))))',
expansionMap: {
  '@0': {
    keyExpression:
      '0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2'
  },
  '@1': {
    keyExpression:
      "[d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*",
    keyPath: '/1/2/3/4/*',
    originPath: "/49'/0'/0'",
    path: "m/49'/0'/0'/1/2/3/4/*",
    // Other relevant properties returned: `pubkey`, `ecpair` & `bip32` interfaces, `masterFingerprint`, etc.
  }
}
```

### Key Expressions and Script Expressions

This library also provides a series of function helpers designed to streamline the generation of `descriptor` strings. These strings can serve as input parameters in the `Output` class constructor. These helpers are nested within the `scriptExpressions` module. You can import them as illustrated below:

```javascript
import { scriptExpressions } from '@bitcoinerlab/descriptors';
```

Within `scriptExpressions`, you will find functions tailored to produce descriptors for a range of commonly utilized scripts. To name a few: `pkhBIP32()`, `shWpkhBIP32()`, `wpkhBIP32()`, `pkhLedger()`, `shWpkhLedger()`, and `wpkhLedger()`.

When using BIP32-based descriptors, the following parameters are required for the `scriptExpressions` functions:

```javascript
pkhBIP32(params: {
  masterNode: BIP32Interface; //bitcoinjs-lib BIP32 - https://github.com/bitcoinjs/bip32
  network?: Network; //A bitcoinjs-lib network
  account: number;
  change?: number | undefined; //0 -> external (receive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string; //You can use change & index or a keyPath such as "/0/0"
  isPublic?: boolean; //Whether to use xpub or xprv
})
```

For functions suffixed with *Ledger* (designed to generate descriptors for Ledger Hardware devices), replace `masterNode` with `ledgerManager`. Detailed information on Ledger integration will be provided in subsequent sections.

The `keyExpressions` category includes functions that generate string representations of key expressions for public keys.

This library includes the following `keyExpressions`: `keyExpressionBIP32` and `keyExpressionLedger`. They can be imported as follows:

```javascript
import {
  keyExpressionBIP32,
  keyExpressionLedger
} from '@bitcoinerlab/descriptors';
```

The parameters required for these functions are:

```javascript
function keyExpressionBIP32({
  masterNode: BIP32Interface; //bitcoinjs-lib BIP32 - https://github.com/bitcoinjs/bip32
  originPath: string;
  change?: number | undefined; //0 -> external (receive), 1 -> internal (change)
  index?: number | undefined | '*';
  keyPath?: string | undefined; //In the case of the Ledger, keyPath must be /<1;0>/number
  isPublic?: boolean;
});
```

For the `keyExpressionLedger` function, you'd use `ledgerManager` instead of `masterNode`. Detailed information on Ledger in subsequent sections.

Both functions will generate strings that fully define BIP32 keys. For example: `[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*`. Read [Bitcoin Core descriptors documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) to learn more about Key Expressions.

### Signers and Finalizers

This library encompasses a PSBT finalizer as well as three distinct signers: ECPair for single-signatures, BIP32, and Ledger (specifically crafted for Ledger Wallet devices, with upcoming support for other devices planned).

To incorporate these functionalities, use the following import statement:

```javascript
import { signers, finalizePsbt } from '@bitcoinerlab/descriptors';
```

For signing operations, utilize the methods provided by the `signers`:

```javascript
// For Ledger
await signers.signLedger({ psbt, ledgerManager });

// For BIP32 - https://github.com/bitcoinjs/bip32
signers.signBIP32({ psbt, masterNode });

// For ECPair - https://github.com/bitcoinjs/ecpair
signers.signECPair({ psbt, ecpair }); // Here, `ecpair` is an instance of the bitcoinjs-lib ECPairInterface
```

<a name="signers-and-finalizers-finalize-psbt-input"></a>

To finalize the `psbt`, there are two approaches:

1. For each unspent output from a previous transaction that you're referencing in the `psbt` as an input to be spent, apply the `output.finalizePsbtInput({ index, psbt })` method. It's essential to specify the exact position (or `index`) of the input in the `psbt` that references this unspent output. This `index` should align with the value returned by the `updatePsbtAsInput` method.

2. Alternatively, you can employ the `finalizePsbt({psbt, outputs })` function. Within this context, `outputs` is an array of previously unspent outputs (each an instance of the `Output` class) that are being referenced and spent by the inputs of the `psbt`. It's crucial to position each item in the `outputs` array to reflect the exact order they're referenced in the `psbt` inputs. Put another way, the order of these `output` entries should coincide with the index values returned by `updatePsbtAsInput`.


### Hardware Wallet Integration

This library currently provides integration with Ledger wallets. Support for more devices is planned.

Before we dive in, note that, in addition to the documentation below, it is highly recommended to visit the [Ledger Playground](https://bitcoinerlab.com/guides/ledger-programming) with an interactive code sandbox of this lib interacting with a Ledger device.

To use this library with Ledger devices, you must first install Ledger support:

```bash
npm install ledger-bitcoin
```

For Ledger device signing, import the necessary functions as follows:

```javascript
import Transport from '@ledgerhq/hw-transport-node-hid'; //or hw-transport-web-hid, for web
import { AppClient } from 'ledger-bitcoin';
import { ledger } from '@bitcoinerlab/descriptors';
```

Then, use the following code to assert that the Ledger app is running Bitcoin Test version 2.1.0 or higher, and to create a new Ledger client:

```javascript
const transport = await Transport.create();
//Throws if not running Bitcoin Test >= 2.1.0
await ledger.assertLedgerApp({
  transport,
  name: 'Bitcoin Test',
  minVersion: '2.1.0'
});

const ledgerClient = new AppClient(transport);
const ledgerManager = { ledgerClient, ledgerState: {}, ecc, network };
```

Here, `transport` is an instance of a Transport object that allows communication with Ledger devices. You can use any of the transports [provided by Ledger](https://github.com/LedgerHQ/ledger-live#libs---libraries).

To register the policies of non-standard descriptors on the Ledger device, use the following code:

```javascript
await ledger.registerLedgerWallet({
  ledgerManager,
  descriptor: wshDescriptor,
  policyName: 'BitcoinerLab'
});
```

This code will auto-skip the policy registration process if it already exists. Please refer to [Ledger documentation](https://github.com/LedgerHQ/app-bitcoin-new/blob/develop/doc/wallet.md) to learn more about their Wallet Policies registration procedures.

Finally, `ledgerManager.ledgerState` is an object used to store information related to Ledger devices. Although Ledger devices themselves are stateless, this object can be used to store information such as xpubs, master fingerprints, and wallet policies. You can pass an initially empty object that will be updated with more information as it is used. The object can be serialized and stored for future use.

<a name="documentation"></a>

## Additional Resources

For more information, refer to the following resources:

- [Guides](https://bitcoinerlab.com/guides): Comprehensive explanations and playgrounds to help you learn how to use the module.
- [Stack Exchange answer](https://bitcoin.stackexchange.com/a/118036/89665): Focused explanation on the constructor, specifically the `signersPubKeys` parameter, and the usage of `updatePsbtAsInput`, `finalizePsbtInput`, `getAddress`, and `getScriptPubKey`.
- [Integration tests](https://github.com/bitcoinerlab/descriptors/tree/main/test/integration): Well-commented code examples showcasing the usage of all functions in the module.
- API Documentation: Auto-generated documentation from the source code, providing detailed information about the library and its methods. To generate the API documentation locally, follow these commands:

  ```bash
  git clone https://github.com/bitcoinerlab/descriptors
  cd descriptors/
  npm install
  npm run docs
  ```

  The generated documentation will be available in the `docs/` directory. Open the `index.html` file to view the documentation.

## Authors and Contributors

The project was initially developed and is currently maintained by [Jose-Luis Landabaso](https://github.com/landabaso). Contributions and help from other developers are welcome.

Here are some resources to help you get started with contributing:

### Building from source

To download the source code and build the project, follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/bitcoinerlab/descriptors.git
```

2. Install the dependencies:

```bash
npm install
```

3. Build the project:

```bash
npm run build
```

This will build the project and generate the necessary files in the `dist` directory.

### Testing

Before committing any code, make sure it passes all tests. First, make sure that you have a Bitcoin regtest node running and that you have set up [this Express-based bitcoind manager](https://github.com/bitcoinjs/regtest-server) running on 127.0.0.1:8080.

The easiest way to set up these services is to use a Docker image that comes preconfigured with them. You can use the following commands to download and run the Docker image:

```bash
docker pull bitcoinerlab/tester
docker run -d -p 8080:8080 -p 60401:60401 -p 3002:3002 bitcoinerlab/tester
```

This will start a container running a Bitcoin regtest node and the bitcoind manager on your machine. Once you have your node and manager set up, you can run the tests using the following command:

```bash
npm run test
```

And, in case you have a Ledger device:

```bash
npm run test:integration:ledger
```

### License

This project is licensed under the MIT License.
