// Distributed under the MIT software license

console.log('Ledger taproot integration tests');

import Transport from '@ledgerhq/hw-transport-node-hid';
import { AppClient } from '@ledgerhq/ledger-bitcoin';
import { mnemonicToSeedSync } from 'bip39';
import { networks, Psbt } from 'bitcoinjs-lib';
import { RegtestUtils } from 'regtest-client';

import * as ecc from '@bitcoinerlab/secp256k1';
import {
  DescriptorsFactory,
  keyExpressionLedger,
  ledger,
  scriptExpressions,
  signers
} from '../../dist/';

const regtestUtils = new RegtestUtils();

const NETWORK = networks.regtest;
const UTXO_VALUE = 20_000;
const FEE = 1_000;
const SOFT_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const { Output, BIP32 } = DescriptorsFactory(ecc);
const { signLedger } = signers;
const { trLedger } = scriptExpressions;
const { registerLedgerWallet, assertLedgerApp } = ledger;

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function runSpendScenario({
  name,
  output,
  ledgerManager,
  expectScriptPath
}: {
  name: string;
  output: InstanceType<typeof Output>;
  ledgerManager: {
    ledgerClient: AppClient;
    ledgerState: Record<string, unknown>;
    ecc: typeof ecc;
    network: typeof NETWORK;
  };
  expectScriptPath: boolean;
}) {
  const destinationAddress = regtestUtils.RANDOM_ADDRESS;
  const { txId, vout } = await regtestUtils.faucetComplex(
    Buffer.from(output.getScriptPubKey()),
    UTXO_VALUE
  );
  const { txHex } = await regtestUtils.fetch(txId);

  const psbt = new Psbt({ network: NETWORK });
  const finalize = output.updatePsbtAsInput({ psbt, txHex, vout });

  const beforeSignInput = psbt.data.inputs[0];
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

  psbt.addOutput({
    address: destinationAddress,
    value: BigInt(UTXO_VALUE - FEE)
  });

  await signLedger({ psbt, ledgerManager });

  const afterSignInput = psbt.data.inputs[0];
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

  const spendTx = psbt.extractTransaction();
  await regtestUtils.broadcast(spendTx.toHex());
  await regtestUtils.mine(1);
  await regtestUtils.verify({
    txId: spendTx.getId(),
    address: destinationAddress,
    vout: 0,
    value: UTXO_VALUE - FEE
  });

  console.log(`${name}: OK`);
}

(async () => {
  let transport;
  try {
    transport = await Transport.create(3000, 3000);
  } catch (err) {
    void err;
    throw new Error(`Error: Ledger device not detected`);
  }

  await assertLedgerApp({
    transport,
    name: 'Bitcoin Test',
    minVersion: '2.1.0'
  });

  const ledgerClient = new AppClient(transport);
  const ledgerManager = {
    ledgerClient,
    ledgerState: {},
    ecc,
    network: NETWORK
  };

  // Scenario 1: Taproot key-path using standard Ledger BIP86 descriptor
  const trKeyPathDescriptor = await trLedger({
    ledgerManager,
    account: 0,
    change: 0,
    index: 0
  });

  await runSpendScenario({
    name: 'ledger taproot key-path spend',
    output: new Output({ descriptor: trKeyPathDescriptor, network: NETWORK }),
    ledgerManager,
    expectScriptPath: false
  });

  // Scenario 2: Taproot script-path (tapscript) with Ledger leaf key
  const originPath = `/86'/1'/0'`;
  const softMasterNode = BIP32.fromSeed(
    mnemonicToSeedSync(SOFT_MNEMONIC),
    NETWORK
  );
  const softXpub = softMasterNode
    .derivePath(`m${originPath}`)
    .neutered()
    .toBase58();
  const internalKeyExpression = `${softXpub}/0/0`;
  const ledgerLeafExpression = await keyExpressionLedger({
    ledgerManager,
    originPath,
    change: 0,
    index: 0
  });
  const scriptPathDescriptor = `tr(${internalKeyExpression},pk(${ledgerLeafExpression}))`;

  await registerLedgerWallet({
    ledgerManager,
    descriptor: scriptPathDescriptor,
    policyName: 'Taproot ScriptPath'
  });

  try {
    await runSpendScenario({
      name: 'ledger taproot script-path spend',
      output: new Output({
        descriptor: scriptPathDescriptor,
        network: NETWORK,
        taprootSpendPath: 'script'
      }),
      ledgerManager,
      expectScriptPath: true
    });
  } catch (err) {
    throw new Error(
      `Error: taproot script-path ledger scenario failed. This may indicate the connected Ledger app/client stack does not support tr(KEY,TREE). Details: ${String(
        err
      )}`
    );
  }
})();
