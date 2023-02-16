Unit tests can be run without any dependency:

```bash
npm run test:unit
```

However, you must have [Docker installed](https://docs.docker.com/get-docker/) in your system to be able to run the integration tests:

```bash
npm run test:integration
```
The command above will download and start the regtest image (if not running already) on Docker.

Command `npm run test` will run both types of tests.

