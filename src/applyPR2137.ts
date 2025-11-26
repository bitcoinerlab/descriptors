//While this PR is not merged: https://github.com/bitcoinjs/bitcoinjs-lib/pull/2137
//The Async functions have not been "fixed"
//Note that a further fix (look for FIX BITCOINERLAB) was done
import type { Psbt, Signer } from 'bitcoinjs-lib';
import { checkForInput } from 'bip174/src/lib/utils';
import type { SignerAsync } from 'ecpair';
import type { PsbtInput } from 'bip174/src/lib/interfaces';
import { tapTweakHash } from 'bitcoinjs-lib/src/payments/bip341';
import { isTaprootInput } from 'bitcoinjs-lib/src/psbt/bip371';
import { taggedHash } from 'bitcoinjs-lib/src/crypto';

interface HDSignerBase {
  /**
   * DER format compressed publicKey buffer
   */
  publicKey: Buffer;
  /**
   * The first 4 bytes of the sha256-ripemd160 of the publicKey
   */
  fingerprint: Buffer;
}
interface HDSigner extends HDSignerBase {
  /**
   * The path string must match /^m(\/\d+'?)+$/
   * ex. m/44'/0'/0'/1/23 levels with ' must be hard derivations
   */
  derivePath(path: string): HDSigner;
  /**
   * Input hash (the "message digest") for the signature algorithm
   * Return a 64 byte signature (32 byte r and 32 byte s in that order)
   */
  sign(hash: Buffer): Buffer;
  /**
   * Adjusts a keypair for Taproot payments by applying a tweak to derive the internal key.
   *
   * In Taproot, a keypair may need to be tweaked to produce an internal key that conforms to the Taproot script.
   * This tweak process involves modifying the original keypair based on a specific tweak value to ensure compatibility
   * with the Taproot address format and functionality.
   */
  tweak(t: Buffer): Signer;
}
interface HDSignerAsync extends HDSignerBase {
  derivePath(path: string): HDSignerAsync;
  sign(hash: Buffer): Promise<Buffer>;
  tweak(t: Buffer): Signer;
}

const toXOnly = (pubKey: Buffer) =>
  pubKey.length === 32 ? pubKey : pubKey.slice(1, 33);

function range(n: number): number[] {
  return [...Array(n).keys()];
}

function tapBranchHash(a: Buffer, b: Buffer): Buffer {
  return taggedHash('TapBranch', Buffer.concat([a, b]));
}

function calculateScriptTreeMerkleRoot(
  leafHashes: Buffer[]
): Buffer | undefined {
  if (!leafHashes || leafHashes.length === 0) {
    return undefined;
  }

  // sort the leaf nodes
  leafHashes.sort(Buffer.compare);

  // create the initial hash node
  let currentLevel = leafHashes;

  // build Merkle Tree
  while (currentLevel.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : left;
      nextLevel.push(
        i + 1 < currentLevel.length ? tapBranchHash(left!, right!) : left
      );
    }
    currentLevel = nextLevel as Buffer[];
  }

  return currentLevel[0];
}

function getTweakSignersFromHD(
  inputIndex: number,
  inputs: PsbtInput[],
  hdKeyPair: HDSigner | HDSignerAsync
): Array<Signer | SignerAsync> {
  const input = checkForInput(inputs, inputIndex);
  if (!input.tapBip32Derivation || input.tapBip32Derivation.length === 0) {
    throw new Error('Need tapBip32Derivation to sign with HD');
  }
  const myDerivations = input.tapBip32Derivation
    .map(bipDv => {
      if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
        return bipDv;
      } else {
        return;
      }
    })
    .filter(v => !!v);
  if (myDerivations.length === 0) {
    throw new Error(
      'Need one tapBip32Derivation masterFingerprint to match the HDSigner fingerprint'
    );
  }

  const signers: Array<Signer | SignerAsync> = myDerivations.map(bipDv => {
    const node = hdKeyPair.derivePath(bipDv!.path);
    if (!bipDv!.pubkey.equals(toXOnly(node.publicKey))) {
      throw new Error('pubkey did not match tapBip32Derivation');
    }

    //FIX BITCOINERLAB:
    //The 3 lines below detect script-path spends and disable key-path tweaking.
    //Reasoning:
    //- In Taproot, key-path spends require tweaking the internal key.
    //- Script-path spends MUST NOT tweak the key; signatures use the raw internal key.
    const input = inputs[inputIndex];
    if (!input) throw new Error('could not find the input');
    if (input.tapLeafScript && input.tapLeafScript.length > 0) return node;

    const h = calculateScriptTreeMerkleRoot(bipDv!.leafHashes);
    const tweakValue = tapTweakHash(toXOnly(node.publicKey), h);

    return node.tweak(tweakValue);
  });
  return signers;
}
function getSignersFromHD(
  inputIndex: number,
  inputs: PsbtInput[],
  hdKeyPair: HDSigner | HDSignerAsync
): Array<Signer | SignerAsync> {
  const input = checkForInput(inputs, inputIndex);
  if (isTaprootInput(input)) {
    return getTweakSignersFromHD(inputIndex, inputs, hdKeyPair);
  }

  if (!input.bip32Derivation || input.bip32Derivation.length === 0) {
    throw new Error('Need bip32Derivation to sign with HD');
  }
  const myDerivations = input.bip32Derivation
    .map(bipDv => {
      if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
        return bipDv;
      } else {
        return;
      }
    })
    .filter(v => !!v);
  if (myDerivations.length === 0) {
    throw new Error(
      'Need one bip32Derivation masterFingerprint to match the HDSigner fingerprint'
    );
  }
  const signers: Array<Signer | SignerAsync> = myDerivations.map(bipDv => {
    const node = hdKeyPair.derivePath(bipDv!.path);
    if (!bipDv!.pubkey.equals(node.publicKey)) {
      throw new Error('pubkey did not match bip32Derivation');
    }
    return node;
  });
  return signers;
}

export const applyPR2137 = (psbt: Psbt) => {
  psbt.signInputHD = function signInputHD(
    inputIndex: number,
    hdKeyPair: HDSigner,
    sighashTypes?: number[]
  ) {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }
    const signers = getSignersFromHD(
      inputIndex,
      this.data.inputs,
      hdKeyPair
    ) as Signer[];
    signers.forEach(signer => this.signInput(inputIndex, signer, sighashTypes));
    return this;
  };

  psbt.signAllInputsHD = function signAllInputsHD(
    hdKeyPair: HDSigner,
    sighashTypes?: number[]
  ) {
    if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
      throw new Error('Need HDSigner to sign input');
    }

    const results: boolean[] = [];
    for (const i of range(psbt.data.inputs.length)) {
      try {
        psbt.signInputHD(i, hdKeyPair, sighashTypes);
        results.push(true);
      } catch (err) {
        void err;
        results.push(false);
      }
    }
    if (results.every(v => v === false)) {
      throw new Error('No inputs were signed');
    }
    return psbt;
  };
};
