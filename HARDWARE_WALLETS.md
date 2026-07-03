# Hardware Wallets

```ts
import { Output, Psbt, networks } from '@bitcoinerlab/descriptors';
import {
  connectors,
  registerWallet,
  scriptExpressions,
  signers
} from '@bitcoinerlab/descriptors/ledger';

const manager = await connectors.nodeHid({
  Output,
  network: networks.bitcoin
});

const descriptor = await scriptExpressions.wpkh({
  manager,
  account: 0,
  change: 0,
  index: '*'
});

await registerWallet({
  manager,
  descriptor,
  policyName: 'Savings'
});

const psbt = new Psbt();
// Add inputs and outputs with Output.updatePsbtAsInput(...)
// and Output.updatePsbtAsOutput(...).

await signers.sign({ psbt, manager });
```

That is the basic shape of a hardware-wallet integration in this library:

1. Connect to the device and create a `manager`.
2. Ask the device for keys and build a descriptor.
3. Register the wallet policy when the device needs it.
4. Build a PSBT with the normal `Output` APIs.
5. Ask the device to sign.

The same idea is used for Ledger and BitBox. The imports and connection method
change, but the high-level flow stays the same.

The examples in this guide use `@bitcoinerlab/descriptors`, the bitcoinjs-ready
package. The same hardware-wallet entrypoints are also available from
`@bitcoinerlab/descriptors-scure`.

## Device Entrypoints

```ts
import * as ledger from '@bitcoinerlab/descriptors/ledger';
import * as bitbox from '@bitcoinerlab/descriptors/bitbox';
```

Hardware-wallet code lives behind device-specific entrypoints. This keeps the
main package usable without installing Ledger or BitBox transport libraries.

Use these entrypoints:

- `@bitcoinerlab/descriptors/ledger`
- `@bitcoinerlab/descriptors/bitbox`
- `@bitcoinerlab/descriptors-scure/ledger`
- `@bitcoinerlab/descriptors-scure/bitbox`

Each device entrypoint exposes the same recommended names:

- `connectors`
- `keyExpression`
- `scriptExpressions`
- `registerWallet`
- `signers`

## Install Device Transports

```bash
npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-node-hid
```

Install these packages if you want to connect to a Ledger from Node.js with HID.

```bash
npm install bitbox-api
```

Install `bitbox-api` if you want to use the built-in BitBox browser, WebHID or
BitBoxBridge connector.

You do not need these packages if your app already has a connected device
client. In that case, use `connectors.fromClient(...)` and pass the client to
this library.

## Connect To A Ledger

```ts
import { Output, networks } from '@bitcoinerlab/descriptors';
import { connectors } from '@bitcoinerlab/descriptors/ledger';

const ledgerState = {};

const manager = await connectors.nodeHid({
  Output,
  network: networks.bitcoin,
  state: ledgerState,
  appName: 'Bitcoin',
  minVersion: '2.1.0'
});
```

The `manager` contains the connected Ledger client, the Bitcoin network, the
`Output` constructor for your backend, and a mutable `state` object.

Keep the `state` object around if your app has a wallet database. It caches
fingerprints, xpubs and registered policies, so the app does not need to repeat
work every time.

If your app already created a Ledger Bitcoin app client with another transport,
use `fromClient(...)` instead:

```ts
const manager = connectors.fromClient({
  client: ledgerClient,
  Output,
  network: networks.bitcoin,
  state: ledgerState
});
```

## Connect To A BitBox

```ts
import { Output, networks } from '@bitcoinerlab/descriptors';
import { connectors } from '@bitcoinerlab/descriptors/bitbox';

const bitboxState = {};

const manager = await connectors.connect({
  mechanism: 'auto',
  Output,
  network: networks.bitcoin,
  state: bitboxState,
  onPairingCode: pairingCode => {
    console.log(`Confirm this pairing code on the BitBox: ${pairingCode}`);
  }
});
```

`connectors.connect(...)` uses `bitbox-api` lazily. It does not import BitBox
code unless you call the connector.

Available BitBox mechanisms are:

- `auto`
- `bridge`
- `webhid`

If your app already has a paired BitBox client, use `fromClient(...)`:

```ts
const manager = connectors.fromClient({
  client: bitboxClient,
  Output,
  network: networks.bitcoin,
  state: bitboxState
});
```

This is the right path for mobile apps and other native runtimes. For example, a
React Native app can provide its own native BitBox client and inject it here.

Pass a Bitcoin `network`, not a BitBox coin string. The adapter maps mainnet to
`btc` and test networks, signet and regtest to `tbtc` for the BitBox API.

## Build Standard Descriptors

```ts
const descriptor = await scriptExpressions.wpkh({
  manager,
  account: 0,
  change: 0,
  index: '*'
});
```

Hardware wallets derive keys from the device. The `scriptExpressions` helpers
ask the device for the right xpub and build a descriptor string for you.

The standard helpers are:

- `scriptExpressions.pkh(...)`
- `scriptExpressions.shWpkh(...)`
- `scriptExpressions.wpkh(...)`
- `scriptExpressions.tr(...)`

Not every device supports every helper. If a device cannot safely display or
sign a descriptor type, the helper throws early.

## Build Custom Descriptors

```ts
import {
  keyExpression,
  registerWallet
} from '@bitcoinerlab/descriptors/bitbox';

const key = await keyExpression({
  manager,
  originPath: "/84'/0'/0'",
  keyPath: '/0/*'
});

const descriptor = `wsh(and_v(v:pk(${key}),older(10)))`;

await registerWallet({
  manager,
  descriptor,
  policyName: 'CSV Savings'
});
```

Use `keyExpression(...)` when the standard helpers are not enough. It returns a
descriptor key expression with origin information and an xpub from the device.

Many hardware wallets need to register non-standard wallet policies before they
can display addresses or sign. `registerWallet(...)` stores what the device
returns in the manager state. If registration is not needed, or the policy is
already known, the helper skips the extra device step when possible.

## Sign And Finalize

```ts
const output = new Output({ descriptor, index: 0, network: networks.bitcoin });
const psbt = new Psbt();

const finalizeInput = output.updatePsbtAsInput({
  psbt,
  txHex: 'PREVIOUS_TRANSACTION_HEX',
  vout: 0
});

const recipient = new Output({
  descriptor: 'addr(bc1qgw6xanldsz959z45y4dszehx4xkuzf7nfhya8x)'
});

recipient.updatePsbtAsOutput({ psbt, value: 10000n });

await signers.sign({ psbt, manager });
finalizeInput({ psbt });
```

Hardware-wallet signing uses the same PSBT that normal descriptor spending uses.
Prepare inputs with `Output.updatePsbtAsInput(...)`, add outputs, ask the device
to sign, then finalize with the function returned by `updatePsbtAsInput(...)`.

Prefer passing the full previous transaction as `txHex`. This gives the device
more information to verify what is being spent. It is especially important for
Segwit inputs.

## BitBox Details

```ts
await bitbox.scriptExpressions.wpkh({ manager, account: 0, index: '*' });
await bitbox.scriptExpressions.tr({ manager, account: 0, index: '*' });
```

These are good standard choices for BitBox single-key accounts.

```ts
await bitbox.scriptExpressions.pkh({ manager, account: 0, index: '*' });
```

This throws. BitBox02 does not support top-level legacy P2PKH descriptors,
`pkh(KEY)`, through the simple account flow. Use `sh(wpkh(KEY))`, `wpkh(KEY)` or
`tr(KEY)` instead.

BitBox also rejects Miniscript hash preimage fragments before address display or
signing:

```text
wsh(and_v(v:pk(KEY),sha256(HASH)))
```

The rejected fragments are `sha256(...)`, `hash256(...)`, `hash160(...)` and
`ripemd160(...)`. BitBox firmware marks these policy fragments unsupported, and
firmware 9.26.1 has been observed to crash while deriving `sha256(...)`
policies.

This restriction is about hash preimages. It is separate from Miniscript
`pkh(KEY)` fragments inside `wsh(...)`. A top-level `pkh(KEY)` account and a
Miniscript `pkh(KEY)` fragment are not the same thing.

## Ledger Details

Ledger wallet policies have stricter key rules than descriptors in general.
This package checks those rules before asking the device to sign.

Ledger policies must use device-compatible key roots:

- Key expressions in a wallet policy must expand into `@i` placeholders.
- Policy key roots must be xpub-type keys, not xprvs or raw public keys.
- All policy key origins must use the same origin path.
- External keys may use an empty origin path.

One practical consequence is that a Ledger can sign at most one key per policy
and input. A policy may contain other keys, but only one of them can be the key
owned by the connected Ledger for that signing operation.

## Real-Device Tests

```bash
npm run build
npm run test:ledger
npm run test:bitbox
```

Unit tests use fake clients and do not need hardware. The commands above are
manual real-device checks.

Run `npm run build` first after changing TypeScript source. The BitBox
integration test imports built files from `dist`, so stale builds can give stale
results.
