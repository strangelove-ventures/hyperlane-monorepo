/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { MysteryMathV1, MysteryMathV1Interface } from "../MysteryMathV1";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "a",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "b",
        type: "uint256",
      },
    ],
    name: "doMath",
    outputs: [
      {
        internalType: "uint256",
        name: "_result",
        type: "uint256",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [],
    name: "getState",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "_var",
        type: "uint256",
      },
    ],
    name: "setState",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "stateVar",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "version",
    outputs: [
      {
        internalType: "uint32",
        name: "",
        type: "uint32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];

const _bytecode =
  "0x60a060405234801561001057600080fd5b50600160e01b60805260016101606100316000398060f952506101606000f3fe608060405234801561001057600080fd5b50600436106100675760003560e01c8063793816ec11610050578063793816ec146100a7578063a9e966b7146100af578063d6c4979c146100ce57610067565b80631865c57d1461006c57806354fd4d5014610086575b600080fd5b6100746100f1565b60408051918252519081900360200190f35b61008e6100f7565b6040805163ffffffff9092168252519081900360200190f35b61007461011b565b6100cc600480360360208110156100c557600080fd5b5035610121565b005b610074600480360360408110156100e457600080fd5b5080359060200135610126565b60005490565b7f000000000000000000000000000000000000000000000000000000000000000081565b60005481565b600055565b019056fea26469706673582212202cd3e240eb7513b7e99ad8aad10be88dc51153cca445d8263caebdc15674f10564736f6c63430007060033";

export class MysteryMathV1__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<MysteryMathV1> {
    return super.deploy(overrides || {}) as Promise<MysteryMathV1>;
  }
  getDeployTransaction(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): MysteryMathV1 {
    return super.attach(address) as MysteryMathV1;
  }
  connect(signer: Signer): MysteryMathV1__factory {
    return super.connect(signer) as MysteryMathV1__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): MysteryMathV1Interface {
    return new utils.Interface(_abi) as MysteryMathV1Interface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): MysteryMathV1 {
    return new Contract(address, _abi, signerOrProvider) as MysteryMathV1;
  }
}