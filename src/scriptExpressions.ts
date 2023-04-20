import type { AppClient } from 'ledger-bitcoin';
import { networks, Network } from 'bitcoinjs-lib';
import type { LedgerState } from './ledger';
import { keyExpressionBIP32, keyExpressionLedger } from './keyExpressions';
import type { BIP32Interface } from 'bip32';

function assertStandardKeyPath(keyPath: string) {
  // Regular expression to match "/change/index" or "/change/*" format
  const regex = /^\/[01]\/(\d+|\*)$/;
  if (!regex.test(keyPath)) {
    throw new Error(
      "Error: Key path must be in the format '/change/index', where change is either 0 or 1 and index is a non-negative integer."
    );
  }
}

function standardExpressionsBIP32Maker(
  purpose: number,
  scriptTemplate: string
) {
  function standardKeyExpressionBIP32({
    masterNode,
    network = networks.bitcoin,
    keyPath,
    account,
    change,
    index,
    isPublic = true
  }: {
    masterNode: BIP32Interface;
    network?: Network;
    account: number;
    change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
    index?: number | undefined | '*';
    keyPath?: string;
    isPublic?: boolean;
  }) {
    const originPath = `/${purpose}'/${
      network === networks.bitcoin ? 0 : 1
    }'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const keyExpression = keyExpressionBIP32({
      masterNode,
      originPath,
      keyPath,
      change,
      index,
      isPublic
    });

    return scriptTemplate.replace('KEYEXPRESSION', keyExpression);
  }
  return standardKeyExpressionBIP32;
}

export const pkhBIP32 = standardExpressionsBIP32Maker(44, 'pkh(KEYEXPRESSION)');
export const shWpkhBIP32 = standardExpressionsBIP32Maker(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);
export const wpkhBIP32 = standardExpressionsBIP32Maker(
  84,
  'wpkh(KEYEXPRESSION)'
);

function standardExpressionsLedgerMaker(
  purpose: number,
  scriptTemplate: string
) {
  async function standardKeyExpressionLedger({
    ledgerClient,
    ledgerState,
    network = networks.bitcoin,
    account,
    keyPath,
    change,
    index
  }: {
    ledgerClient: AppClient;
    ledgerState: LedgerState;
    network?: Network;
    account: number;
    keyPath?: string;
    change?: number | undefined; //0 -> external (reveive), 1 -> internal (change)
    index?: number | undefined | '*';
  }) {
    const originPath = `/${purpose}'/${
      network === networks.bitcoin ? 0 : 1
    }'/${account}'`;
    if (keyPath !== undefined) assertStandardKeyPath(keyPath);
    const keyExpression = await keyExpressionLedger({
      ledgerClient,
      ledgerState,
      originPath,
      keyPath,
      change,
      index
    });

    return scriptTemplate.replace('KEYEXPRESSION', keyExpression);
  }
  return standardKeyExpressionLedger;
}

export const pkhLedger = standardExpressionsLedgerMaker(
  44,
  'pkh(KEYEXPRESSION)'
);
export const shWpkhLedger = standardExpressionsLedgerMaker(
  49,
  'sh(wpkh(KEYEXPRESSION))'
);
export const wpkhLedger = standardExpressionsLedgerMaker(
  84,
  'wpkh(KEYEXPRESSION)'
);
