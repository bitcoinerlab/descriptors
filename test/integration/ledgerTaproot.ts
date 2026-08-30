// Distributed under the MIT software license

console.log('Ledger taproot integration tests');

import { RegtestUtils } from 'regtest-client';

import * as ecc from '@bitcoinerlab/secp256k1';
import { DescriptorsFactory, keyExpressionBIP32, networks } from '../../dist/';
import * as ledger from '../../dist/ledger/index';
import { createBitcoinjsLib } from '../../dist/bitcoinjs';
import { createScureLib } from '../../dist/scure';
import { createMasterNode } from '../helpers/keys';
import {
  createPsbt,
  isScurePsbt,
  psbtAddOutput,
  psbtToHex,
  psbtToTxId
} from '../helpers/psbt';

const regtestUtils = new RegtestUtils();
const isScure = process.env['BITCOIN_LIB'] === 'scure';

const NETWORK = networks.regtest;
const UTXO_VALUE = 20_000;
const FEE = 1_000;
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const { Output } = DescriptorsFactory(
  isScure ? createScureLib() : createBitcoinjsLib(ecc)
);

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function runSpendScenario({
  name,
  output,
  ledgerSession,
  expectScriptPath
}: {
  name: string;
  output: InstanceType<typeof Output>;
  ledgerSession: ledger.Session;
  expectScriptPath: boolean;
}) {
  const destinationAddress = regtestUtils.RANDOM_ADDRESS;
  const { txId, vout } = await regtestUtils.faucetComplex(
    Buffer.from(output.getScriptPubKey()),
    UTXO_VALUE
  );
  const { txHex } = await regtestUtils.fetch(txId);

  const psbt = createPsbt(isScure, NETWORK);
  const finalize = output.updatePsbtAsInput({ psbt, txHex, vout });

  const beforeSignInput = isScurePsbt(psbt)
    ? psbt.getInput(0)
    : psbt.data.inputs[0];
  if (!beforeSignInput) throw new Error(`Error: ${name} input not found`);

  if (expectScriptPath) {
    assert(
      Boolean(beforeSignInput.tapLeafScript?.length),
      `Error: ${name} expected tapLeafScript to be populated`
    );
    assert(
      Boolean(beforeSignInput.tapBip32Derivation?.length),
      `Error: ${name} expected tapBip32Derivation to be populated`
    );
  }

  psbtAddOutput(
    psbt,
    {
      address: destinationAddress,
      value: BigInt(UTXO_VALUE - FEE)
    },
    NETWORK
  );

  await ledger.signers.sign({ psbt, session: ledgerSession });

  const afterSignInput = isScurePsbt(psbt)
    ? psbt.getInput(0)
    : psbt.data.inputs[0];
  if (!afterSignInput)
    throw new Error(`Error: ${name} input not found after signing`);

  if (expectScriptPath) {
    assert(
      Boolean(afterSignInput.tapScriptSig?.length),
      `Error: ${name} expected tapScriptSig after signing`
    );
  } else {
    assert(
      Boolean(afterSignInput.tapKeySig),
      `Error: ${name} expected tapKeySig`
    );
    assert(
      !afterSignInput.tapScriptSig || afterSignInput.tapScriptSig.length === 0,
      `Error: ${name} expected no tapScriptSig for key-path`
    );
  }

  finalize({ psbt });

  await regtestUtils.broadcast(psbtToHex(psbt));
  await regtestUtils.mine(1);
  await regtestUtils.verify({
    txId: psbtToTxId(psbt),
    address: destinationAddress,
    vout: 0,
    value: UTXO_VALUE - FEE
  });

  console.log(`${name}: OK`);
}

let closeSession = async () => {};
(async () => {
  const ledgerSession = await ledger.connect({
    driver: {
      transport: import('@ledgerhq/hw-transport-node-hid'),
      bitcoinApi: import('@ledgerhq/ledger-bitcoin'),
      app: { name: 'Bitcoin Test', minVersion: '2.1.0' }
    },
    network: NETWORK,
    store: {}
  });
  closeSession = ledgerSession.close;

  // Scenario 1: Taproot key-path using standard Ledger BIP86 descriptor
  const trKeyPathDescriptor = await ledger.scriptExpressions.tr({
    session: ledgerSession,
    account: 0,
    change: 0,
    index: 0
  });

  await runSpendScenario({
    name: 'ledger taproot key-path spend',
    output: new Output({ descriptor: trKeyPathDescriptor, network: NETWORK }),
    ledgerSession,
    expectScriptPath: false
  });

  // Scenario 2: Taproot script-path (tapscript) with Ledger leaf key
  const originPath = `/86'/1'/0'`;
  const internalKeyExpression = keyExpressionBIP32({
    masterNode: createMasterNode(SOFT_MNEMONIC, NETWORK, isScure),
    originPath,
    change: 0,
    index: 0
  });
  const ledgerLeafExpression = await ledger.keyExpression({
    session: ledgerSession,
    originPath,
    change: 0,
    index: 0
  });
  const scriptPathDescriptor = `tr(${internalKeyExpression},pk(${ledgerLeafExpression}))`;

  await ledger.registerPolicy({
    session: ledgerSession,
    descriptor: scriptPathDescriptor,
    name: 'Taproot ScriptPath'
  });

  try {
    await runSpendScenario({
      name: 'ledger taproot script-path spend',
      output: new Output({
        descriptor: scriptPathDescriptor,
        network: NETWORK,
        taprootSpendPath: 'script'
      }),
      ledgerSession,
      expectScriptPath: true
    });
  } catch (err) {
    throw new Error(
      `Error: taproot script-path ledger scenario failed. This may indicate the connected Ledger app/client stack does not support tr(KEY,TREE). Details: ${String(
        err
      )}`
    );
  }
})().finally(() => closeSession());
