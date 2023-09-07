import { Address, Domain } from '@hyperlane-xyz/utils';

import { ERC20Metadata } from '../config';

export type MinimalTokenMetadata = Omit<ERC20Metadata, 'totalSupply'>;

export interface TransferParams {
  weiAmountOrId: string | number;
  recipient: Address;

  // Solana-specific params
  // Included here optionally to keep Adapter types simple
  fromTokenAccount?: Address;
  fromAccountOwner?: Address;
  mailbox?: Address;
}

export interface TransferRemoteParams extends TransferParams {
  destination: Domain;
  txValue?: string;
}

export interface ITokenAdapter {
  getBalance(address?: Address): Promise<string>;
  getMetadata(isNft?: boolean): Promise<MinimalTokenMetadata>;
  populateApproveTx(TransferParams: TransferParams): unknown | Promise<unknown>;
  populateTransferTx(
    TransferParams: TransferParams,
  ): unknown | Promise<unknown>;
}

export interface IHypTokenAdapter extends ITokenAdapter {
  getDomains(): Promise<Domain[]>;
  getRouterAddress(domain: Domain): Promise<Buffer>;
  getAllRouters(): Promise<Array<{ domain: Domain; address: Buffer }>>;
  quoteGasPayment(destination: Domain): Promise<string>;
  populateTransferRemoteTx(
    TransferParams: TransferRemoteParams,
  ): unknown | Promise<unknown>;
}
