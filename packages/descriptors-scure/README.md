# @bitcoinerlab/descriptors-scure

Scure-ready package for `@bitcoinerlab/descriptors-core`.

For scure/noble users this is the simplest install path:

```bash
npm install @bitcoinerlab/descriptors-scure
```

It bundles the scure/noble family dependencies and exposes pre-bound helpers
such as `Output`, `expand`, `btc`, `HDKey` and `secp256k1`, while still
exporting `DescriptorsFactory` for advanced flows.

Most users can import directly from the package:

```javascript
import { Output, btc, signers } from '@bitcoinerlab/descriptors-scure';
```
