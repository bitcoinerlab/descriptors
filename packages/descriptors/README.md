# @bitcoinerlab/descriptors

Bitcoinjs-ready package for Bitcoin descriptor work.

For most users this is the default package to install:

```bash
npm install @bitcoinerlab/descriptors
```

It bundles the bitcoinjs family dependencies and exposes pre-bound helpers such
as `Output`, `expand`, `ECPair`, `BIP32`, `Psbt` and `ecc` at the top level.

Most users can import directly from the package:

```javascript
import { Output, Psbt, ECPair, signers } from '@bitcoinerlab/descriptors';
```

`DescriptorsFactory(...)` is still available only for 3.x backwards
compatibility and is planned to stop being a public preset-package API in the
next major release.
