# Hardware Wallets

```ts
import { Output, Psbt, networks } from '@bitcoinerlab/descriptors';
import {
  connectors,
  registerWallet,
  scriptExpressions,
  signers
} from '@bitcoinerlab/descriptors/ledger';

const session = await connectors.connect({
  mode: 'node-hid',
  Output,
  network: networks.bitcoin
});

const descriptor = await scriptExpressions.wpkh({
  session,
  account: 0,
  change: 0,
  index: '*'
});

await registerWallet({
  session,
  descriptor,
  policyName: 'Savings'
});

const psbt = new Psbt();
// Add inputs and outputs with Output.updatePsbtAsInput(...)
// and Output.updatePsbtAsOutput(...).

await signers.sign({ psbt, session });
```

That is the basic shape of a hardware-wallet integration in this library:

1. Connect to the device and create a `session`.
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

## Common Hardware-Wallet API

Ledger and BitBox entrypoints expose the same common API shape:

| API | Purpose |
| --- | --- |
| `type Session` | Connected device client plus `Output`, network and app-owned state. |
| `type State` | Persistable app-owned state for cached keys and wallet policy metadata. |
| `connectors.connect(...)` | Build a session with a built-in explicit transport mode. |
| `connectors.fromClient(...)` | Build a session from an already connected device client. |
| `getVersion({ session })` | Read the device/app version exposed by the vendor API. |
| `getMasterFingerprint({ session })` | Read and cache the BIP32 master fingerprint. |
| `getXpub({ session, originPath })` | Read and cache an account xpub. |
| `keyExpression(...)` | Build a descriptor key expression from device keys. |
| `scriptExpressions.*(...)` | Build standard account descriptors. |
| `registerWallet(...)` | Register or locally remember non-standard wallet policies. |
| `displayAddress(...)` | Ask the device to display an address for verification. |
| `signers.sign(...)` | Ask the device to sign a PSBT. |
| `signers.signInput(...)` | Convenience wrapper for single-input signing flows. |
| `signMessage(...)` | Ask the device to sign a legacy/Electrum Bitcoin message for a descriptor address. |

`signMessage(...)` has the same public shape for Ledger and BitBox:
`signMessage({ session, message, descriptor, change?, index })`. It returns a
65-byte `Uint8Array` legacy/Electrum Bitcoin message signature. It does not
produce BIP322 signatures.

## Install Device Transports

Ledger built-in modes require `@ledgerhq/ledger-bitcoin` plus the transport for
the mode you use:

| Ledger mode | Install |
| --- | --- |
| `node-hid` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-node-hid` |
| `webhid` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-webhid` |
| `webusb` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-webusb` |

```bash
npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-node-hid
```

This installs Ledger support for Node.js HID.

BitBox built-in modes all use `bitbox-api`:

| BitBox mode | Install |
| --- | --- |
| `webhid` | `npm install bitbox-api` |
| `bridge` | `npm install bitbox-api` |
| `webhid-or-bridge` | `npm install bitbox-api` |

```bash
npm install bitbox-api
```

This installs support for the built-in BitBox browser WebHID and BitBoxBridge
connectors.

You do not need these packages if your app already has a connected device
client. In that case, use `connectors.fromClient(...)` and pass the client to
this library.

## Connect To A Ledger

```ts
import { Output, networks } from '@bitcoinerlab/descriptors';
import { connectors } from '@bitcoinerlab/descriptors/ledger';

const ledgerState = {};

const session = await connectors.connect({
  mode: 'node-hid',
  Output,
  network: networks.bitcoin,
  state: ledgerState,
  appName: 'Bitcoin',
  minVersion: '2.1.0',
  openTimeout: 3000,
  listenTimeout: 3000
});
```

The `session` contains the connected Ledger client, the Bitcoin network, the
`Output` constructor for your backend, and a mutable `state` object.

Available Ledger modes are:

- `node-hid`
- `webhid`
- `webusb`

WebHID and WebUSB are browser transports. They must be called from a browser
context that can show the device permission prompt, usually from a user gesture.
`openTimeout` and `listenTimeout` are only for `node-hid`; browser modes use the
Ledger browser transport defaults.

If your app already created a Ledger Bitcoin app client with another transport,
use `fromClient(...)` instead:

```ts
const session = connectors.fromClient({
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

const state = {};

const session = await connectors.connect({
  mode: 'webhid-or-bridge',
  Output,
  network: networks.bitcoin,
  state,
  onPairingCode: pairingCode => {
    console.log(`Confirm this pairing code on the BitBox: ${pairingCode}`);
  }
});
```

`connectors.connect(...)` uses `bitbox-api` lazily. It does not import BitBox
code unless you call the connector.

Available BitBox modes are:

- `webhid`
- `bridge`
- `webhid-or-bridge`

`webhid-or-bridge` is the `bitbox-api` fallback flow: it tries WebHID when
available and otherwise attempts BitBoxBridge. For React Native and other native
apps, use `fromClient(...)` instead of a built-in mode.

If your app already has a paired BitBox-compatible provider client, use
`fromClient(...)`. This is the right path for mobile apps and other native
runtimes. For example, a React Native app can provide its own native BitBox
client and inject it here.

```ts
const session = connectors.fromClient({
  client,
  Output,
  network: networks.bitcoin,
  state
});
```

Pass a Bitcoin `network`, not a BitBox coin string. The connector maps mainnet to
`btc` and test networks, signet and regtest to `tbtc` for the BitBox API.

The connector also hides legacy xpub encodings from application code. Descriptors
already carry the script type, so BitBox xpub requests use only `xpub` on
mainnet and `tpub` on non-mainnet networks. Formats such as `ypub`, `zpub`,
`upub` or `vpub` are not part of this library's BitBox descriptor flow.

## Keep Session State

Do not store a `session` itself. A session contains a live device client. Store
the `state` object instead, then pass that state back when you create the next
session.

The state object has two jobs:

- It caches the master fingerprint and xpubs so the app does not need to ask the
  device every time.
- It stores wallet policy metadata that this library needs later to display
  addresses or sign PSBTs for non-standard wallets.

The details are slightly different by device:

- Ledger state stores the registration receipt returned by the Ledger app
  (`policyId` and `policyHmac`). Keep it with your wallet record. Without it,
  the app cannot reuse that registered Ledger policy without registering again.
- BitBox state stores the app-side policy mapping, including multisig account
  data when needed. The BitBox can tell whether a script config is already
  registered, but it does not give this library a list of wallet policies to
  rebuild that mapping later.

If you drop BitBox state, you can call `registerWallet(...)` again for each
wallet descriptor after reconnecting. The helper checks the device first, avoids
duplicate on-device registration when possible, and repopulates local state.

If you serialize state as JSON, encode byte arrays such as fingerprints and
Ledger policy ids/hmacs as hex or base64 in your app database.

## Build Standard Descriptors

```ts
const descriptor = await scriptExpressions.wpkh({
  session,
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
  session,
  originPath: "/84'/0'/0'",
  keyPath: '/0/*'
});

const descriptor = `wsh(and_v(v:pk(${key}),older(10)))`;

await registerWallet({
  session,
  descriptor,
  policyName: 'CSV Savings'
});
```

Use `keyExpression(...)` when the standard helpers are not enough. It returns a
descriptor key expression with origin information and an xpub from the device.

Many hardware wallets need to register non-standard wallet policies before they
can display addresses or sign. `registerWallet(...)` stores what the device
returns in the session state. If registration is not needed, or the policy is
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

await signers.sign({ psbt, session });
finalizeInput({ psbt });
```

Hardware-wallet signing uses the same PSBT that normal descriptor spending uses.
Prepare inputs with `Output.updatePsbtAsInput(...)`, add outputs, ask the device
to sign, then finalize with the function returned by `updatePsbtAsInput(...)`.

Prefer passing the full previous transaction as `txHex`. This gives the device
more information to verify what is being spent. It is especially important for
Segwit inputs.

## Sign Messages

```ts
import { signMessage } from '@bitcoinerlab/descriptors/ledger';

const signature = await signMessage({
  session,
  message: 'hello',
  descriptor,
  change: 0,
  index: 0
});
```

The returned signature is the 65-byte legacy/Electrum Bitcoin message format:
one header byte followed by the compact ECDSA signature. String messages are
encoded as UTF-8 before they are passed to the device.

Message signing is intentionally limited to single-key account descriptors:

- Ledger supports `pkh(KEY)`, `sh(wpkh(KEY))` and `wpkh(KEY)`.
- BitBox supports `sh(wpkh(KEY))` and `wpkh(KEY)`.

Taproot message signing is not exposed. Multisig, Miniscript and other
non-standard policies are also not supported by this helper.

## BitBox Details

BitBox adds these device-specific extensions on top of the common API:

- `connectors.connect(...)` with `webhid`, `bridge` or `webhid-or-bridge` mode
  for built-in `bitbox-api` connection flows.
- `formatUnit` in connector params and sessions to choose how amounts are shown
  while signing.

```ts
await bitbox.scriptExpressions.wpkh({ session, account: 0, index: '*' });
await bitbox.scriptExpressions.tr({ session, account: 0, index: '*' });
```

These are good standard choices for BitBox single-key accounts.

```ts
await bitbox.scriptExpressions.pkh({ session, account: 0, index: '*' });
```

This throws. BitBox02 does not support top-level legacy P2PKH descriptors,
`pkh(KEY)`, through the simple account flow. Use `sh(wpkh(KEY))`, `wpkh(KEY)` or
`tr(KEY)` instead.

For message signing, BitBox also rejects top-level `pkh(KEY)` and `tr(KEY)`
descriptors before calling the device.

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

BitBox signing also accepts a display unit preference:

```ts
const session = await bitbox.connectors.connect({
  mode: 'webhid-or-bridge',
  Output,
  network: networks.bitcoin,
  formatUnit: 'sat'
});
```

`formatUnit` only affects how amounts are shown on the BitBox screen. It does
not change the descriptor, PSBT, policy or signatures. If omitted, the connector
passes `default`.

## Ledger Details

Ledger adds these device-specific extensions on top of the common API:

- `connectors.connect(...)` with `node-hid`, `webhid` or `webusb` mode for
  built-in Ledger connection flows.
- `assertLedgerApp(...)` to verify the open Ledger app and minimum version when
  you manage the transport yourself.
- Deprecated 3.x compatibility names such as `LedgerManager`,
  `registerLedgerWallet(...)`, `keyExpressionLedger(...)`,
  `signers.signLedger(...)` and `scriptExpressions.wpkhLedger(...)`.

For message signing, Ledger supports standard single-key `pkh(KEY)`,
`sh(wpkh(KEY))` and `wpkh(KEY)` descriptors. `tr(KEY)` and non-standard policies
throw before calling the device.

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
