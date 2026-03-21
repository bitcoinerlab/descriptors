// Copyright (c) 2025 Jose-Luis Landabaso - https://bitcoinerlab.com
// Distributed under the MIT software license

import {
  isScureTransaction,
  type ScureTransactionLike,
  type ECPairInterfaceLike,
  type BIP32InterfaceLike,
  type ScureHDKeyLike,
  type PsbtLike
} from './bitcoinLib';
import { toPsbt } from './psbt';
import { toBIP32Interface, toECPairInterface } from './keyInterfaces';
import { isTaprootInput, tapTweakHash } from './bitcoinjs-lib-internals';
import {
  importAndValidateLedgerBitcoin,
  comparePolicies,
  LedgerPolicy,
  LedgerManager,
  ledgerPolicyFromPsbtInput
} from './ledger';
type DefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';
declare class PartialSignature {
  readonly pubkey: Uint8Array;
  readonly signature: Uint8Array;
  readonly tapleafHash?: Uint8Array;
  constructor(
    pubkey: Uint8Array,
    signature: Uint8Array,
    tapleafHash?: Uint8Array
  );
}

/**
 * This applies a bitcoinjs-lib speciffic patch.
 * This won't be run if using the scure lib
 */
function ensureBitcoinjsHdPatch(psbt: PsbtLike): void {
  let BitcoinjsPsbt;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    ({ Psbt: BitcoinjsPsbt } = require('bitcoinjs-lib'));
  } catch (error) {
    void error;
    return;
  }
  if (!BitcoinjsPsbt || !(psbt instanceof BitcoinjsPsbt)) return;

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { applyPR2137 } = require('./adapters/applyPR2137');
  applyPR2137(psbt);
}

function range(n: number): number[] {
  return [...Array(n).keys()];
}
/**
 * Signs a specific input of a PSBT with an ECPair.
 *
 * Unlike bitcoinjs-lib's native `psbt.signInput()`, this function automatically detects
 * if the input is a Taproot input and internally tweaks the key if needed.
 *
 * This behavior matches how `signInputBIP32` works, where the BIP32 node is automatically
 * tweaked for Taproot inputs. In contrast, bitcoinjs-lib's native implementation requires
 * manual pre-tweaking of ECPair signers for Taproot inputs.
 *
 * @see https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - The PSBT to sign
 * @param {number} params.index - The input index to sign
 * @param {ECPairInterface} params.ecpair - The ECPair to sign with
 */
export function signInputECPair({
  psbt,
  index,
  ecpair
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  ecpair: ECPairInterfaceLike | Uint8Array;
}): void {
  ecpair = toECPairInterface(ecpair);
  psbt = toPsbt(psbt);
  //psbt.signInput(index, ecpair); <- Replaced for the code below
  //that can handle taproot inputs automatically.
  //See https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
  const input = psbt.data.inputs[index];
  if (!input) throw new Error('Invalid index');
  if (isTaprootInput(input)) {
    // If script-path (tapLeafScript present) -> DO NOT TWEAK
    if (input.tapLeafScript && input.tapLeafScript.length > 0)
      psbt.signInput(index, ecpair);
    else {
      const hash = tapTweakHash(ecpair.publicKey.slice(1, 33), undefined);
      const tweakedEcpair = ecpair.tweak(hash);
      psbt.signInput(index, tweakedEcpair);
    }
  } else psbt.signInput(index, ecpair);
}
/**
 * Signs all inputs of a PSBT with an ECPair.
 *
 * This function improves upon bitcoinjs-lib's native `psbt.signAllInputs()` by automatically
 * handling Taproot inputs. For each input, it detects if it's a Taproot input and internally
 * tweaks the key if needed.
 *
 * This creates consistency with the BIP32 signing methods (`signBIP32`/`signInputBIP32`),
 * which also automatically handle key tweaking for Taproot inputs. In contrast, bitcoinjs-lib's
 * native implementation requires users to manually pre-tweak ECPair signers for Taproot inputs.
 *
 * With this implementation, you can use a single ECPair to sign both Taproot and non-Taproot
 * inputs in the same PSBT, similar to how `signBIP32` allows using a common node for both types.
 *
 * @see https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
 *
 * @param {Object} params - The parameters object
 * @param {PsbtLike} params.psbt - The PSBT to sign
 * @param {ECPairInterface} params.ecpair - The ECPair to sign with
 */
export function signECPair({
  psbt,
  ecpair
}: {
  psbt: PsbtLike | ScureTransactionLike;
  ecpair: ECPairInterfaceLike | Uint8Array;
}): void {
  ecpair = toECPairInterface(ecpair);
  psbt = toPsbt(psbt);
  //psbt.signAllInputs(ecpair); <- replaced for the code below that handles
  //taptoot automatically.
  //See https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137#issuecomment-2713264848
  const results: boolean[] = [];
  for (const index of range(psbt.data.inputs.length)) {
    try {
      signInputECPair({ psbt, index, ecpair });
      results.push(true);
    } catch (err) {
      void err;
      results.push(false);
    }
  }
  if (results.every(v => v === false)) {
    throw new Error('No inputs were signed');
  }
}

/**
 * Signs one input of a `@scure/btc-signer` transaction with a raw private key.
 *
 * This helper is intended for scure users that work directly with a `Uint8Array`
 * private key and may not use bitcoinjs-lib `ECPair` types.
 *
 * If you are signing a bitcoinjs-lib PSBT input, use {@link signInputECPair}
 * and pass a bitcoinjs-lib `ECPair` signer.
 *
 * @param {Object} params - The parameters object
 * @param {ScureTransactionLike} params.psbt - The scure transaction to sign
 * @param {number} params.index - The input index to sign
 * @param {Uint8Array} params.privKey - The secp256k1 private key (32 bytes)
 * @throws If `psbt` is not a scure transaction
 */
export function signInputPrivKey({
  psbt,
  index,
  privKey
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  privKey: Uint8Array;
}): void {
  if (!isScureTransaction(psbt)) {
    throw new Error(
      'Error: signInputPrivKey is only supported with @scure/btc-signer transactions. ' +
        'Use signInputECPair for bitcoinjs-lib PSBTs.'
    );
  }
  signInputECPair({ psbt, index, ecpair: privKey });
}

/**
 * Signs all inputs of a `@scure/btc-signer` transaction with a raw private key.
 *
 * This helper is intended for scure users that work directly with a `Uint8Array`
 * private key and may not use bitcoinjs-lib `ECPair` types.
 *
 * If you are signing a bitcoinjs-lib PSBT, use {@link signECPair} and pass a
 * bitcoinjs-lib `ECPair` signer.
 *
 * @param {Object} params - The parameters object
 * @param {ScureTransactionLike} params.psbt - The scure transaction to sign
 * @param {Uint8Array} params.privKey - The secp256k1 private key (32 bytes)
 * @throws If `psbt` is not a scure transaction
 */
export function signPrivKey({
  psbt,
  privKey
}: {
  psbt: PsbtLike | ScureTransactionLike;
  privKey: Uint8Array;
}): void {
  if (!isScureTransaction(psbt)) {
    throw new Error(
      'Error: signPrivKey is only supported with @scure/btc-signer transactions. ' +
        'Use signECPair for bitcoinjs-lib PSBTs.'
    );
  }
  signECPair({ psbt, ecpair: privKey });
}

export function signInputBIP32({
  psbt,
  index,
  node
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  node: BIP32InterfaceLike | ScureHDKeyLike;
}): void {
  node = toBIP32Interface(node);
  psbt = toPsbt(psbt);
  ensureBitcoinjsHdPatch(psbt);
  psbt.signInputHD(index, node);
}

export function signBIP32({
  psbt,
  masterNode
}: {
  psbt: PsbtLike | ScureTransactionLike;
  masterNode: BIP32InterfaceLike | ScureHDKeyLike;
}): void {
  masterNode = toBIP32Interface(masterNode);
  psbt = toPsbt(psbt);
  ensureBitcoinjsHdPatch(psbt);
  psbt.signAllInputsHD(masterNode);
}

const ledgerSignaturesForInputIndex = (
  index: number,
  ledgerSignatures: [number, PartialSignature][]
) =>
  ledgerSignatures
    .filter(([i]: [number, PartialSignature]) => i === index)
    .map(
      ([_i, partialSignature]: [number, PartialSignature]) => partialSignature
    );

function addLedgerSignaturesToInput({
  psbt,
  index,
  ledgerSignatures
}: {
  psbt: PsbtLike;
  index: number;
  ledgerSignatures: [number, PartialSignature][];
}) {
  const input = psbt.data.inputs[index];
  if (!input) throw new Error(`Error: input ${index} not available`);

  const signatures = ledgerSignaturesForInputIndex(index, ledgerSignatures);
  if (signatures.length === 0)
    throw new Error(`Error: no ledger signatures found for input ${index}`);

  if (isTaprootInput(input)) {
    // Ledger returns per-input signatures as [pubkey, signature, tapleafHash?].
    // For taproot we must map them to PSBT taproot fields (not partialSig):
    // - signatures with tapleafHash -> tapScriptSig[] (script-path)
    // - signature without tapleafHash -> tapKeySig (key-path)
    // A taproot input may contain script-path signatures, key-path signature,
    // or both in edge cases; each must be written to its corresponding field.
    const tapScriptSig = signatures
      .filter((sig: PartialSignature) => sig.tapleafHash)
      .map((sig: PartialSignature) => ({
        pubkey: sig.pubkey,
        signature: sig.signature,
        leafHash: sig.tapleafHash!
      }));
    const tapKeySigs = signatures.filter(
      (sig: PartialSignature) => !sig.tapleafHash
    );

    if (tapScriptSig.length > 0) {
      psbt.updateInput(index, { tapScriptSig });
    }

    if (tapKeySigs.length > 1)
      throw new Error(
        `Error: expected at most one tapKeySig for input ${index}`
      );
    const tapKeySig = tapKeySigs[0]?.signature;
    if (tapKeySig) {
      psbt.updateInput(index, { tapKeySig });
    }

    if (tapScriptSig.length === 0 && !tapKeySig)
      throw new Error(
        `Error: no valid taproot ledger signatures found for input ${index}`
      );
  } else {
    const partialSig = signatures.map((sig: PartialSignature) => ({
      pubkey: sig.pubkey,
      signature: sig.signature
    }));
    psbt.updateInput(index, { partialSig });
  }
}

/**
 * Signs an input of the `psbt` where the keys are controlled by a Ledger
 * device.
 *
 * The function will throw an error if it's unable to sign the input.
 */
export async function signInputLedger({
  psbt,
  index,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  ledgerManager: LedgerManager;
}): Promise<void>;
export async function signInputLedger({
  psbt,
  index,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  index: number;
  ledgerManager: LedgerManager;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const { ledgerClient } = ledgerManager;
  const { DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  const policy = await ledgerPolicyFromPsbtInput({
    psbt,
    index,
    ledgerManager
  });
  if (!policy) throw new Error(`Error: the ledger cannot sign this pstb input`);

  let ledgerSignatures;
  if (policy.policyName && policy.policyHmac && policy.policyId) {
    //non-standard policy
    const walletPolicy = new WalletPolicy(
      policy.policyName,
      policy.ledgerTemplate,
      policy.keyRoots
    );

    const walletHmac = policy.policyHmac as unknown as Parameters<
      typeof ledgerClient.signPsbt
    >[2];
    ledgerSignatures = await ledgerClient.signPsbt(
      psbt.toBase64(),
      walletPolicy,
      walletHmac
    );
  } else {
    //standard policy
    ledgerSignatures = await ledgerClient.signPsbt(
      psbt.toBase64(),
      new DefaultWalletPolicy(
        policy.ledgerTemplate as DefaultDescriptorTemplate,
        policy.keyRoots[0]!
      ),
      null
    );
  }

  addLedgerSignaturesToInput({ psbt, index, ledgerSignatures });
}

/**
 * Signs the inputs of the `psbt` where the keys are controlled by a Ledger
 * device.
 *
 * `signLedger` can sign multiple inputs of the same wallet policy in a single
 * pass by grouping inputs by their wallet policy type before the signing
 * process.
 *
 * The function will throw an error if it's unable to sign any input.
 */
export async function signLedger({
  psbt,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  ledgerManager: LedgerManager;
}): Promise<void>;
export async function signLedger({
  psbt,
  ledgerManager
}: {
  psbt: PsbtLike | ScureTransactionLike;
  ledgerManager: LedgerManager;
}): Promise<void> {
  psbt = toPsbt(psbt);
  const { ledgerClient } = ledgerManager;
  const { DefaultWalletPolicy, WalletPolicy, AppClient } =
    (await importAndValidateLedgerBitcoin(
      ledgerClient
    )) as typeof import('@ledgerhq/ledger-bitcoin');
  if (!(ledgerClient instanceof AppClient))
    throw new Error(`Error: pass a valid ledgerClient`);

  const ledgerPolicies = [];
  for (let index = 0; index < psbt.data.inputs.length; index++) {
    const policy = await ledgerPolicyFromPsbtInput({
      psbt,
      index,
      ledgerManager
    });
    if (policy) ledgerPolicies.push(policy);
  }
  if (ledgerPolicies.length === 0)
    throw new Error(`Error: there are no inputs which could be signed`);

  //cluster unique LedgerPolicies
  const uniquePolicies: LedgerPolicy[] = [];
  for (const policy of ledgerPolicies) {
    if (
      !uniquePolicies.find((uniquePolicy: LedgerPolicy) =>
        comparePolicies(uniquePolicy, policy)
      )
    )
      uniquePolicies.push(policy);
  }

  for (const uniquePolicy of uniquePolicies) {
    let ledgerSignatures;
    if (
      uniquePolicy.policyName &&
      uniquePolicy.policyHmac &&
      uniquePolicy.policyId
    ) {
      //non-standard policy
      const walletPolicy = new WalletPolicy(
        uniquePolicy.policyName,
        uniquePolicy.ledgerTemplate,
        uniquePolicy.keyRoots
      );

      const walletHmac = uniquePolicy.policyHmac as unknown as Parameters<
        typeof ledgerClient.signPsbt
      >[2];
      ledgerSignatures = await ledgerClient.signPsbt(
        psbt.toBase64(),
        walletPolicy,
        walletHmac
      );
    } else {
      //standard policy
      ledgerSignatures = await ledgerClient.signPsbt(
        psbt.toBase64(),
        new DefaultWalletPolicy(
          uniquePolicy.ledgerTemplate as DefaultDescriptorTemplate,
          uniquePolicy.keyRoots[0]!
        ),
        null
      );
    }

    const signedIndexes = [
      ...new Set(ledgerSignatures.map(([index]) => index))
    ];
    for (const index of signedIndexes) {
      addLedgerSignaturesToInput({ psbt, index, ledgerSignatures });
    }
  }
}
