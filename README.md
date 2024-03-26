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

Furthermore, we've meticulously documented our API. For an in-depth look into Classes, functions, and types, head over [here](https://bitcoinerlab.com/modules/descriptors/api).

To use this library (and accompanying libraries), you can install them using:

```bash
npm install @bitcoinerlab/descriptors
npm install @bitcoinerlab/miniscript
npm install @bitcoinerlab/secp256k1
```

The library can be split into four main parts:

- The `Output` class is the central component for managing descriptors. It facilitates the creation of outputs to receive funds and enables the signing and finalization of PSBTs (Partially Signed Bitcoin Transactions) for spending UTXOs (Unspent Transaction Outputs).
- PSBT signers and finalizers, which are used to manage the signing and finalization of PSBTs.
- `keyExpressions` and `scriptExpressions`, which provide functions to create key and standard descriptor expressions (strings) from structured data.
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

For miniscript-based descriptors, the `signersPubKeys` parameter in the constuctor becomes particularly important. It specifies the spending path of a previous output with multiple spending paths. Detailed information about the constructor parameters, including `signersPubKeys`, can be found in [the API documentation](https://bitcoinerlab.com/modules/descriptors/api/classes/_Internal_.Output.html#constructor) and in [this Stack Exchange answer](https://bitcoin.stackexchange.com/a/118036/89665).

The `Output` class [offers various helpful methods](https://bitcoinerlab.com/modules/descriptors/api/classes/_Internal_.Output.html), including `getAddress()`, which returns the address associated with the descriptor, `getScriptPubKey()`, which returns the `scriptPubKey` for the descriptor, `expand()`, which decomposes a descriptor into its elemental parts, `updatePsbtAsInput()` and `updatePsbtAsOutput()`.

The `updatePsbtAsInput()` method is an essential part of the library, responsible for adding an input to the PSBT corresponding to the UTXO  described by the descriptor. Additionally, when the descriptor expresses an absolute time-spending condition, such as "This UTXO can only be spent after block N", `updatePsbtAsInput()` adds timelock information to the PSBT.

To call `updatePsbtAsInput()`, use the following syntax:

```javascript
import { Psbt } from 'bitcoinjs-lib';
const psbt = new Psbt();
const inputFinalizer = output.updatePsbtAsInput({ psbt, txHex, vout });
```

Here, `psbt` refers to an instance of the [bitcoinjs-lib Psbt class](https://github.com/bitcoinjs/bitcoinjs-lib). The parameter `txHex` denotes a hex string that serializes the previous transaction containing this output. Meanwhile, `vout` is an integer that marks the position of the output within that transaction.

The method returns the `inputFinalizer()` function. This finalizer function completes a PSBT input by adding the unlocking script (`scriptWitness` or `scriptSig`) that satisfies the previous output's spending conditions. Bear in mind that both `scriptSig` and `scriptWitness` incorporate signatures. As such, you should complete all necessary signing operations before calling `inputFinalizer()`. Detailed [explanations on the `inputFinalizer` method](#signers-and-finalizers-finalize-psbt-input) can be found in the Signers and Finalizers section.

Conversely, `updatePsbtAsOutput` allows you to add an output to a PSBT. For instance, to configure a `psbt` that sends `10,000` sats to the SegWit address `bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x`:

```javascript
const recipientOutput = 
 new Output({ descriptor: `addr(bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x)` });
recipientOutput.updatePsbtAsOutput({ psbt, value: 10000 });
```

For further information on using the `Output` class, refer to the [comprehensive guides](https://bitcoinerlab.com/guides) that offer explanations and playgrounds to help learn the module. For specific details on the methods, refer directly to [the API](https://bitcoinerlab.com/modules/descriptors/api/classes/_Internal_.Output.html). For insights into the constructor, especially regarding the `signersPubKeys` parameter, as well as the usage of `updatePsbtAsInput`, `getAddress`, and `getScriptPubKey`, see this detailed [Stack Exchange answer](https://bitcoin.stackexchange.com/a/118036/89665).

#### Parsing Descriptors with `expand()`

The `expand()` function serves as a mechanism to parse Bitcoin descriptors, unveiling a detailed breakdown of the descriptor's content. There are two main pathways to utilize this function:

##### 1. Directly from an `Output` Instance

If you have already instantiated the `Output` class and created an output, you can directly use the [`expand()` method](https://bitcoinerlab.com/modules/descriptors/api/classes/_Internal_.Output.html#expand) on that `Output` instance. This method provides a straightforward way to parse descriptors without the need for additional utilities.

```javascript
const output = new Output({ descriptor: "your-descriptor-here" });
const result = output.expand();
```

##### 2. Through the `DescriptorsFactory`

If you haven't instantiated the `Output` class or simply prefer a standalone utility, the `DescriptorsFactory` provides an `expand()` function that allows you to directly parse the descriptor. For a comprehensive understanding of all the function arguments, refer to [this reference](https://bitcoinerlab.com/modules/descriptors/api/functions/DescriptorsFactory.html#DescriptorsFactory). Here's how you can use it:

```javascript
const { expand } = descriptors.DescriptorsFactory(ecc);
const result = expand({
  descriptor: "sh(wsh(andor(pk(0252972572d465d016d4c501887b8df303eee3ed602c056b1eb09260dfa0da0ab2),older(8640),pk([d34db33f/49'/0'/0']tpubDCdxmvzJ5QBjTN8oCjjyT2V58AyZvA1fkmCeZRC75QMoaHcVP2m45Bv3hmnR7ttAwkb2UNYyoXdHVt4gwBqRrJqLUU2JrM43HippxiWpHra/1/2/3/4/*))))"
});
```

Regardless of your chosen pathway, the outcome from `expand()` grants an insightful exploration into the descriptor's structure. For an exhaustive list of return properties, you can refer to [the API](https://bitcoinerlab.com/modules/descriptors/api/types/Expansion.html).

For illustration, given the descriptor above, the corresponding `expandedExpression` and a section of the `expansionMap` would appear as:

```javascript
{
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
    //...
}
```

### Signers and Finalizers

This library encompasses a PSBT finalizer as well as three distinct signers: ECPair for single-signatures, BIP32, and Ledger (specifically crafted for Ledger Wallet devices, with upcoming support for other devices planned).

To incorporate these functionalities, use the following import statement:

```javascript
import { signers } from '@bitcoinerlab/descriptors';
```

For signing operations, utilize the methods provided by the [`signers`](https://bitcoinerlab.com/modules/descriptors/api/modules/signers.html):

```javascript
// For Ledger
await signers.signLedger({ psbt, ledgerManager });

// For BIP32 - https://github.com/bitcoinjs/bip32
signers.signBIP32({ psbt, masterNode });

// For ECPair - https://github.com/bitcoinjs/ecpair
signers.signECPair({ psbt, ecpair }); // Here, `ecpair` is an instance of the bitcoinjs-lib ECPairInterface
```

Detailed information on Ledger integration will be provided in subsequent sections.

<a name="signers-and-finalizers-finalize-psbt-input"></a>

#### Finalizing the `psbt`

When finalizing the `psbt`, the [`updatePsbtAsInput` method](https://bitcoinerlab.com/modules/descriptors/api/classes/_Internal_.Output.html#updatePsbtAsInput) plays a key role. When invoked, the `output.updatePsbtAsInput()` sets up the `psbt` by designating the output as an input and, if required, adjusts the transaction locktime. In addition, it returns a `inputFinalizer` function tailored for this specific `psbt` input.

##### Procedure:

1. For each unspent output from a previous transaction that you're referencing in a `psbt` as an input to be spent, call the `updatePsbtAsInput` method:

   ```javascript
   const inputFinalizer = output.updatePsbtAsInput({ psbt, txHex, vout });
   ```

2. Once you've completed the necessary signing operations on the `psbt`, use the returned finalizer function on each input:

   ```javascript
   inputFinalizer({ psbt });
   ```

##### Important Notes:

- The finalizer function returned from `updatePsbtAsInput` adds the necessary unlocking script (`scriptWitness` or `scriptSig`) that satisfies the `Output`'s spending conditions. Remember, both `scriptSig` and `scriptWitness` contain signatures. Ensure that all necessary signing operations are completed before finalizing.

- When using `updatePsbtAsInput`, the `txHex` parameter is crucial. For Segwit inputs, you can choose to pass `txId` and `value` instead of `txHex`. However, ensure the accuracy of the `value` to avoid potential fee attacks. When unsure, use `txHex` and skip `txId` and `value`.

- Hardware wallets require the [full `txHex` for Segwit](https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd).

### Key Expressions and Script Expressions

This library also provides a series of function helpers designed to streamline the generation of `descriptor` strings. These strings can serve as input parameters in the `Output` class constructor. These helpers are nested within the `scriptExpressions` module. You can import them as illustrated below:

```javascript
import { scriptExpressions } from '@bitcoinerlab/descriptors';
```

Within the `scriptExpressions` module, there are functions designed to generate descriptors for commonly used scripts. Some examples include `pkhBIP32()`, `shWpkhBIP32()`, `wpkhBIP32()`, `pkhLedger()`, `shWpkhLedger()`, and `wpkhLedger()`. Refer to [the API](https://bitcoinerlab.com/modules/descriptors/api/modules/scriptExpressions.html#expand) for a detailed list and further information.

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

For functions suffixed with *Ledger* (designed to generate descriptors for Ledger Hardware devices), replace `masterNode` with `ledgerManager`. Detailed information on Ledger integration will be provided in the following section.

The `keyExpressions` category includes functions that generate string representations of key expressions for public keys.

This library includes the following `keyExpressions`: [`keyExpressionBIP32`](https://bitcoinerlab.com/modules/descriptors/api/functions/keyExpressionBIP32.html) and [`keyExpressionLedger`](https://bitcoinerlab.com/modules/descriptors/api/functions/keyExpressionLedger.html). They can be imported as follows:

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

For the `keyExpressionLedger` function, you'd use `ledgerManager` instead of `masterNode`.

Both functions will generate strings that fully define BIP32 keys. For example:
```text
[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*
```
Read [Bitcoin Core descriptors documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md) to learn more about Key Expressions.

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

The [API reference for the ledger module](https://bitcoinerlab.com/modules/descriptors/api/variables/ledger.html) provides a comprehensive list of functions related to the Ledger Hardware Wallet, along with detailed explanations of their parameters and behavior.

<a name="documentation"></a>

## Additional Resources

For more information, refer to the following resources:

- **[Guides](https://bitcoinerlab.com/guides)**: Comprehensive explanations and playgrounds to help you learn how to use the module.
- **[API](https://bitcoinerlab.com/modules/descriptors/api)**: Dive into the details of the Classes, functions, and types.
- **[Stack Exchange answer](https://bitcoin.stackexchange.com/a/118036/89665)**: Focused explanation on the constructor, specifically the `signersPubKeys` parameter, and the usage of `updatePsbtAsInput`, `getAddress`, and `getScriptPubKey`.
- **[Integration tests](https://github.com/bitcoinerlab/descriptors/tree/main/test/integration)**: Well-commented code examples showcasing the usage of all functions in the module.
- **Local Documentation**: Generate comprehensive API documentation from the source code:

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
