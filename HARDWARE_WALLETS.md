# Hardware Wallets

```ts
import { Output, Psbt, networks } from '@bitcoinerlab/descriptors';
import {
  connect,
  registerPolicy,
  scriptExpressions,
  signers
} from '@bitcoinerlab/descriptors/ledger';

const store = {};

const session = await connect({
  driver: {
    transport: import('@ledgerhq/hw-transport-node-hid'),
    bitcoinApi: import('@ledgerhq/ledger-bitcoin'),
    app: { name: 'Bitcoin', minVersion: '2.1.0' }
  },
  network: networks.bitcoin,
  store
});

try {
  const descriptor = await scriptExpressions.wpkh({
    session,
    account: 0,
    change: 0,
    index: '*'
  });

  await registerPolicy({
    session,
    descriptor,
    name: 'Savings'
  });

  const psbt = new Psbt();
  // Add inputs and outputs with Output.updatePsbtAsInput(...)
  // and Output.updatePsbtAsOutput(...).

  await signers.sign({ psbt, session });
} finally {
  await session.close();
}
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
| `type Session` | Owned device connection plus network and app-owned store. |
| `type Store` | JSON-safe app-owned store for cached keys and wallet policy metadata. |
| `connect(...)` | Build an owned, closeable session from an imported device driver. |
| `getVersion({ session })` | Read the device/app version exposed by the vendor API. |
| `getMasterFingerprint({ session })` | Read and cache the BIP32 master fingerprint. |
| `getXpub({ session, originPath })` | Read and cache an account xpub. |
| `keyExpression(...)` | Build a descriptor key expression from device keys. |
| `scriptExpressions.*(...)` | Build standard account descriptors. |
| `registerPolicy(...)` | Register or locally remember non-standard policies. |
| `displayAddress(...)` | Ask the device to display an address for verification. |
| `signers.sign(...)` | Ask the device to sign a PSBT. |
| `signers.signInput(...)` | Convenience wrapper for single-input signing flows. |
| `signMessage(...)` | Ask the device to sign a legacy/Electrum Bitcoin message for a descriptor address. |

`signMessage(...)` has the same public shape for Ledger and BitBox:
`signMessage({ session, message, descriptor, change?, index? })`. It returns a
65-byte `Uint8Array` legacy/Electrum Bitcoin message signature. It does not
produce BIP322 signatures.

## Address Position Params

`displayAddress(...)` and `signMessage(...)` derive the concrete device key path
from the descriptor. Pass position params only when the descriptor still needs
them:

- Fixed descriptor, such as `wpkh(KEY/0/7)`: pass neither `change` nor `index`.
- Ranged fixed-branch descriptor, such as `wpkh(KEY/0/*)`: pass `index` only.
- Multipath ranged descriptor, such as `wpkh(KEY/**)` or `wpkh(KEY/<0;1>/*)`: pass both `change` and `index`.

`index` is only for ranged descriptors. `change` is only for descriptors with a
multipath branch selector. Passing unnecessary params is rejected so the address
shown by the device cannot differ from the descriptor you supplied.

## Install Device Transports

Install `@ledgerhq/ledger-bitcoin` plus the Ledger transport your app uses:

| Ledger driver | Install |
| --- | --- |
| `node-hid` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-node-hid` |
| `webhid` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-webhid` |
| `webusb` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-webusb` |
| `react-native-hid` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/react-native-hid` |
| `react-native-ble` | `npm install @ledgerhq/ledger-bitcoin @ledgerhq/react-native-hw-transport-ble` |

```bash
npm install @ledgerhq/ledger-bitcoin @ledgerhq/hw-transport-node-hid
```

This installs Ledger support for Node.js HID.

Install the BitBox driver your app uses:

| BitBox driver | Install |
| --- | --- |
| `webhid` | `npm install bitbox-api` |
| `bridge` | `npm install bitbox-api` |
| `webhid-or-bridge` | `npm install bitbox-api` |
| React Native BLE/USB | `npm install @bitcoinerlab/bitbox-react-native` |

```bash
npm install bitbox-api
```

This installs support for BitBox browser WebHID and BitBoxBridge connections.

Pass each selected package as a literal import in the driver. This keeps the
dependency visible to Metro and other bundlers. Ledger receives separate
`driver.transport` and `driver.bitcoinApi` modules. BitBox receives one
`driver.module` provider.

## Connect To A Ledger

```ts
import { networks } from '@bitcoinerlab/descriptors';
import { connect } from '@bitcoinerlab/descriptors/ledger';

const ledgerStore = {};

const session = await connect({
  driver: {
    transport: import('@ledgerhq/hw-transport-node-hid'),
    bitcoinApi: import('@ledgerhq/ledger-bitcoin'),
    openTimeout: 3000,
    listenTimeout: 3000,
    app: { name: 'Bitcoin', minVersion: '2.1.0' }
  },
  network: networks.bitcoin,
  store: ledgerStore
});
```

The `session` contains the connected Ledger client, injected Bitcoin API, Bitcoin
network, and mutable `store` object. It owns the opened transport, so call
`session.close()` when finished.

Each Ledger package supplies one transport, so no mode is needed. When
`driver.device` is omitted, descriptors calls the transport's normal `create()`
method. Ledger transports document this as opening the first available device.
Applications that support several devices should use the transport's
`list()`/`listen()` API and pass the selected device.

Pass `driver.app: { name, minVersion }` to check the open Ledger app before the
session is returned. If `driver.app` is omitted, this explicit check is skipped.

WebHID and WebUSB are browser transports. They must be called from a browser
context that can show the device permission prompt, usually from a user gesture.
Browser transports use their normal browser permission prompt. Driver timeouts
are optional; omit them to use the transport defaults.

### Ledger React Native Setup

Ledger React Native transports are native modules. They do not work in Expo Go.
Use a development build, `npx expo prebuild`, `npx expo run:ios`,
`npx expo run:android`, or EAS Build.

| Ledger mode | Platform | Expo app config | Native permissions | Runtime prompt |
| --- | --- | --- | --- | --- |
| `react-native-hid` | Android USB only | No Ledger plugin is required. Rebuild after installing the package. | The package adds Android USB host support. There is no iOS USB mode. | Android asks for USB permission when the transport opens the device. |
| `react-native-ble` | iOS and Android BLE | Add the `react-native-ble-plx` config plugin. | iOS needs a Bluetooth usage message. Android needs Bluetooth scan/connect permissions and usually location for scanning. | Android needs runtime permission requests before scanning. iOS shows the Bluetooth prompt from the system. |

For BLE in Expo, install `react-native-ble-plx` in the app and add its config
plugin. The Ledger BLE transport uses this package under the hood, and Expo uses
the plugin to write native Bluetooth settings.

```bash
npx expo install react-native-ble-plx
```

```json
{
  "expo": {
    "plugins": [
      [
        "react-native-ble-plx",
        {
          "bluetoothAlwaysPermission": "Allow $(PRODUCT_NAME) to connect to your Ledger over Bluetooth."
        }
      ]
    ]
  }
}
```

For bare React Native BLE apps, add the same native settings yourself:
`NSBluetoothAlwaysUsageDescription` in `Info.plist`, and Android Bluetooth
permissions in `AndroidManifest.xml`. After changing native permissions or Expo
plugins, rebuild the native app. An OTA JavaScript update is not enough.

Ledger's React Native transports expect `global.Buffer` in many apps. If your
runtime does not provide it, install `buffer` and set it before importing Ledger
code:

```ts
import { Buffer } from 'buffer';

global.Buffer = global.Buffer ?? Buffer;
```

### Ledger React Native USB/HID

Use `react-native-hid` for Android USB/HID. It is not an iOS transport.

```ts
import * as LedgerHID from '@ledgerhq/react-native-hid';
import * as LedgerBitcoin from '@ledgerhq/ledger-bitcoin';
import { networks } from '@bitcoinerlab/descriptors';
import { connect } from '@bitcoinerlab/descriptors/ledger';

const devices = await LedgerHID.default.list();
const device = devices[0]; // Let the user choose in a real app.

const session = await connect({
  driver: {
    transport: LedgerHID,
    bitcoinApi: LedgerBitcoin,
    device
  },
  network: networks.bitcoin,
  store: {}
});
```

Your app still owns the UI. Show the device list, let the user pick one, handle
permission denial, and tell the user to open the Bitcoin app on the Ledger.

### Ledger React Native BLE

Use `react-native-ble` for Bluetooth Ledger devices. It works through Ledger's
React Native BLE transport, which uses `react-native-ble-plx` under the hood.

```ts
import * as LedgerBLE from '@ledgerhq/react-native-hw-transport-ble';
import * as LedgerBitcoin from '@ledgerhq/ledger-bitcoin';
import { networks } from '@bitcoinerlab/descriptors';
import { connect } from '@bitcoinerlab/descriptors/ledger';

// First scan with LedgerBLE.default.listen(...) and let the user choose a device.
// The chosen device object, or a saved device.id string, can be used here.
const session = await connect({
  driver: {
    transport: LedgerBLE,
    bitcoinApi: LedgerBitcoin,
    device,
    openTimeout: 10000
  },
  network: networks.bitcoin,
  store: {}
});
```

For explicit selection, scan with the driver before calling `connect(...)`. If
`driver.device` is omitted, the Ledger transport
uses its normal `create()` behavior and opens the first discovered Ledger. In
both cases the app must handle Bluetooth state and runtime permissions. On
Android 12 and newer, ask for `BLUETOOTH_SCAN` and `BLUETOOTH_CONNECT`. Unless
the app is configured with `neverForLocation` and that path has been tested,
also ask for `ACCESS_FINE_LOCATION`. Older Android versions normally need
`ACCESS_FINE_LOCATION`. On iOS, add `NSBluetoothAlwaysUsageDescription`.

Ledger BLE pairing and bonding are handled by the operating system and Ledger's
BLE transport. The phone and Ledger may show a code that the user compares and
confirms through the native Bluetooth prompt, but the transport does not expose
that code to JavaScript. Consequently, Ledger's `driver` has no
`onPairingCode` callback. Ledger USB/HID does not have a connection-pairing
step; device unlocking and confirmations for addresses, policies and signatures
are separate from transport pairing.

This is a conservative Android runtime permission helper:

```ts
import { PermissionsAndroid, Platform } from 'react-native';

async function requestLedgerBlePermissions() {
  if (Platform.OS !== 'android') return true;

  const apiLevel = Number(Platform.Version);
  const permissions =
    apiLevel >= 31
      ? [
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
          PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
          PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
        ]
      : [PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION];

  const result = await PermissionsAndroid.requestMultiple(permissions);
  return permissions.every(
    permission => result[permission] === PermissionsAndroid.RESULTS.GRANTED
  );
}
```

## Connect To A BitBox

```ts
import { networks } from '@bitcoinerlab/descriptors';
import { connect } from '@bitcoinerlab/descriptors/bitbox';

const store = {};

const session = await connect({
  driver: {
    module: import('bitbox-api'),
    mode: 'webhid-or-bridge',
    onPairingCode: pairingCode => {
      console.log(`Confirm this pairing code on the BitBox: ${pairingCode}`);
    }
  },
  network: networks.bitcoin,
  store
});
```

The application imports `bitbox-api` and descriptors handles its unlock and
pairing flow. `onPairingCode` is required because a new pairing may need the app
to show a code that the user compares with the BitBox display. The callback is
not called when the persisted pairing skips code confirmation.

Available BitBox modes are:

- `webhid`
- `bridge`
- `webhid-or-bridge`

`webhid-or-bridge` is the `bitbox-api` fallback flow: it tries WebHID when
available and otherwise attempts BitBoxBridge. Since `bitbox-api` exposes more
than one connection mechanism, `driver.mode` is required. A driver exposing one
supported mechanism does not need a mode.

For React Native BitBox apps, pass `@bitcoinerlab/bitbox-react-native` as the
driver. That package supports BLE and Android USB.

```bash
npx expo install @bitcoinerlab/bitbox-react-native
npx expo install expo-dev-client
```

Add its config plugin when using Expo prebuild or EAS Build:

```json
{
  "expo": {
    "plugins": ["expo-dev-client", "@bitcoinerlab/bitbox-react-native"]
  }
}
```

The BitBox React Native plugin adds the iOS Bluetooth usage text and the Android
Bluetooth and USB manifest entries used by its native transports. It does not
work in Expo Go; use a development build or a production native build.
Unlike the `bitbox-api` browser and bridge flow, this native driver does not use
`onPairingCode`; native Bluetooth bonding and provider pairing are handled below
the descriptors API.

```ts
import { networks } from '@bitcoinerlab/descriptors';
import { connect } from '@bitcoinerlab/descriptors/bitbox';

const session = await connect({
  driver: {
    module: import('@bitcoinerlab/bitbox-react-native'),
    mode: 'ble',
    timeoutMs: 60_000
  },
  network: networks.bitcoin,
  store: {}
});

try {
  // Use keyExpression(...), registerPolicy(...), displayAddress(...),
  // and signers.sign(...) with this session.
} finally {
  await session.close();
}
```

Use `mode: 'usb'` for Android USB. If a BitBox driver exposes both BLE and USB
and `driver.mode` is omitted, descriptors throws an error listing both choices.
When no device is supplied, the native provider uses its normal first-match
behavior. Apps that support several BitBoxes can use the provider's listing API
and pass the selected record in `driver.device`:

```ts
const module = await import('@bitcoinerlab/bitbox-react-native');
const devices = await module.discoverBitBoxNovaBleDevices({
  scanDurationMs: 5000
});
const device = await chooseDevice(devices);

const session = await connect({
  driver: { module, mode: 'ble', device },
  network: networks.bitcoin,
  store: {}
});
```

For Android USB, use `listAttachedBitBoxUsbDevices()`. USB device IDs identify
the current attachment and should not be persisted across reconnects.

Pass a Bitcoin `network`, not a BitBox coin string. The connector maps mainnet to
`btc` and test networks, signet and regtest to `tbtc` for the BitBox API.

The connector also hides legacy xpub encodings from application code. Descriptors
already carry the script type, so BitBox xpub requests use only `xpub` on
mainnet and `tpub` on non-mainnet networks. Formats such as `ypub`, `zpub`,
`upub` or `vpub` are not part of this library's BitBox descriptor flow.

## Persist Store

Do not store a `session` itself. A session contains a live device client. Store
the `store` object instead, then pass that store back when you create the next
session.

The store object has two jobs:

- It caches the master fingerprint and xpubs so the app does not need to ask the
  device every time.
- It stores wallet policy metadata that this library needs later to display
  addresses or sign PSBTs for non-standard wallets.

Sessions created by `connect(...)` read the connected device fingerprint. An
empty store is bound to that fingerprint. If a persisted store belongs to a
different device, connection fails and the newly opened driver is closed.

The store is plain JSON. Persist it directly with `JSON.stringify(store)` and
load it with `JSON.parse(...)` before creating the next session.

The details are slightly different by device:

- Ledger store stores the registration receipt returned by the Ledger app
  (`policyId` and `policyHmac`). Keep it with your wallet record. Without it,
  the app cannot reuse that registered Ledger policy without registering again.
- BitBox store stores the app-side policy mapping. BitBox registration returns
  no id or HMAC. The device can tell whether one exact script config is already
  registered, but it does not give this library a list of wallet policies to
  rebuild that mapping later.

If you drop BitBox store, you can call `registerPolicy(...)` again for each
wallet descriptor after reconnecting. The helper checks the device first, avoids
duplicate on-device registration when possible, and repopulates local store.
The current `bitbox-api` exposes register/check calls, but no unregister or
delete call. Clearing your app store only forgets the local mapping; removing the
device-side registration must be done outside this library, for example through
BitBox device/app management if available, or by resetting the device.

For BitBox multisig, still pass normal descriptor syntax such as
`wsh(sortedmulti(...))`. The library keeps the public store descriptor-based and
converts internally to BitBox native multisig when possible, so the device can
show its native multisig UX. Other non-standard descriptors, including ordered
`wsh(multi(...))`, use generic BitBox policy configs because ordered multisig is
not the same policy as sorted multisig. Physical BitBox devices accept ordered
`wsh(multi(...))` registration and address display through that generic policy
path.

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
  registerPolicy
} from '@bitcoinerlab/descriptors/bitbox';

const key = await keyExpression({
  session,
  originPath: "/84'/0'/0'",
  keyPath: '/0/*'
});

const descriptor = `wsh(and_v(v:pk(${key}),older(10)))`;

await registerPolicy({
  session,
  descriptor,
  name: 'CSV Savings'
});
```

Use `keyExpression(...)` when the standard helpers are not enough. It returns a
descriptor key expression with origin information and an xpub from the device.

Many hardware wallets need to register non-standard policies before they
can display addresses or sign. `registerPolicy(...)` stores what the device
returns in the session store. If registration is not needed, or the policy is
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

- `driver.mode` selects one mechanism when the imported module exposes several.
- `driver.onPairingCode` is required for `bitbox-api` drivers.
- `driver.formatUnit` chooses how amounts are shown while signing.

```ts
await bitbox.scriptExpressions.wpkh({ session, account: 0, index: '*' });
await bitbox.scriptExpressions.tr({ session, account: 0, index: '*' });
```

These are good standard choices for BitBox single-key accounts.

For non-standard policies, BitBox has the same user-facing two-step flow as
Ledger: register first, then receive or sign. The difference is what the device
returns. Ledger returns `policyId` and `policyHmac`, which the app must persist.
BitBox returns no receipt. It stores the approval internally on the device, while
the app persists `BitBoxStore.policies` so this library can rebuild the same
script config for future address display and signing.

This means `registerPolicy(...)` is safe to call again after reconnecting. If the
BitBox already knows the script config, the helper repopulates app-side store
without asking for a duplicate on-device registration. If the BitBox does not
know it, the user approves it on the device.

BitBox has three Bitcoin script-config paths:

- Standard single-key descriptors use simple configs and do not need policy
  registration.
- `wsh(sortedmulti(...))` is converted internally to BitBox native multisig.
- Miniscript and ordered `wsh(multi(...))` use generic policy configs.

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
const store = {};

const session = await bitbox.connect({
  driver: {
    module: import('bitbox-api'),
    mode: 'webhid-or-bridge',
    onPairingCode: code => showPairingCode(code),
    formatUnit: 'sat'
  },
  network: networks.bitcoin,
  store
});
```

`driver.formatUnit` only affects how amounts are shown on the BitBox screen. It
does not change the descriptor, PSBT, policy or signatures. If omitted, the
connector passes `default`.

## Ledger Details

Ledger adds these device-specific extensions on top of the common API:

- `driver.transport` accepts an imported Node, browser or React Native transport.
- `driver.bitcoinApi` accepts the imported `@ledgerhq/ledger-bitcoin` module.
- `driver.device` selects a discovered device; when omitted, the transport uses
  its normal first-device `create()` behavior.
- `driver.app` optionally checks the open app name and minimum version.
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
