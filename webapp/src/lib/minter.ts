import React from "react";
import { Contract, Abi } from "starknet";
import { useStarknet } from "../providers/StarknetProvider";
import { sha3Raw, stripHexPrefix, toHex, padLeft, toBN } from "web3-utils"
import { utils } from "ethers"
import * as BN from "bn.js";

import MINTER from "./abi/minter.json";

const ADDRESS =
  "0x036486801b8f42e950824cba55b2df8cccb0af2497992f807a7e1d9abd2c6ba1";

export function useMinterContract(): Contract | undefined {
  const { library } = useStarknet();
  const [contract, setContract] = React.useState<Contract | undefined>(
    undefined
  );

  React.useEffect(() => {
    setContract(new Contract(MINTER as Abi[], ADDRESS, library));
  }, [library]);

  return contract;
}

function packInts64(input: string): Array<BN> {
  let array = [];
  for (let s of input.match(/.{1,16}/g)!) {
    array.push(toBN(s));
  }
  return array;
}

function packBigInt3(input: string): Array<BN> {
  let a = [];
  const base = toBN(2).pow(toBN(86));
  let num = toBN(input);
  for (let _ of [0,1,2]) { // how to create for loop with unused variable?
    const quotient = num.div(base);
    const residue = num.mod(base);
    num = quotient;
    a.push(residue);
  }
  return a;
}

function encodeProof(proof: Array<string>) {
  let flatProof : Array<BN> = []
  let flatProofSizesBytes = []
  let flatProofSizesWords = []

  for (let proofElement of proof) {
    const packedProofElement : Array<BN> = packInts64(proofElement);
    flatProof.push(...packedProofElement);
    flatProofSizesBytes.push(stripHexPrefix(proofElement).length/2);
    flatProofSizesWords.push(packedProofElement.length);
  }

  return [
    flatProof,
    flatProofSizesBytes,
    flatProofSizesWords,
  ]
}

// Encode call arguments for the "mint" method of the Minter contract
export async function encodeCallArgs(
  provider: any,
  ethAccount: string,
  starknetAccount_: string,
  token: string,
  blockNumber: number,
  storageSlot: string,
  balance: string,
) {
  const number = "0x"+blockNumber.toString(16)
  const block = await provider?.send("eth_getBlockByNumber", [number, false]);

  // Get storage key
  let pos = padLeft(stripHexPrefix(ethAccount.toLowerCase()), 64)
  pos += padLeft(stripHexPrefix(toHex(storageSlot)), 64)
  const storageKey = sha3Raw("0x"+pos)

  // Sign and encode attestation message
  const starknetAccount = packInts64(stripHexPrefix(starknetAccount_));
  const stateRoot = packInts64(stripHexPrefix(block.stateRoot));
  const packedStorageKey = packInts64(storageKey);

  const message = "0xdeadbeef";
  const packedMessage = packInts64(message);
  const rawSignature = await provider?.getSigner().signMessage(message);
  const signature = utils.splitSignature(rawSignature);

  // TODO
  const R_y = packBigInt3(signature.r);

  // Request proof
  const proof = await provider?.send("eth_getProof", [
      token, 
      [storageKey], 
      number]);
  const accountProof = proof.accountProof;
  const storageProof = proof.storageProof[0];
  console.log(proof);

  // Encode proofs
  const [
    accountProofsConcat,
    accountProofSizesWords,
    accountProofSizesBytes] = encodeProof(accountProof);
  const [
    storageProofsConcat,
    storageProofSizesWords,
    storageProofSizesBytes] = encodeProof(storageProof.proof);
  
  return [
    toBN(starknetAccount_),
    toBN(balance),
    accountProof.length,
    storageProof.proof.length,
    packInts64(stripHexPrefix(token)), // address
    stateRoot,
    packInts64(stripHexPrefix(proof.codeHash)),
    packInts64(padLeft(stripHexPrefix(toHex(storageSlot)), 64)),
    packBigInt3(stripHexPrefix(proof.storageHash)),
    // Signed state signature
    packedMessage,
    packedMessage.length,
    message.length/2,
    packBigInt3(signature.r),
    R_y,
    packBigInt3(signature.s),
    signature.recoveryParam + 27,
    packInts64(stripHexPrefix(storageProof.key)),
    packInts64(stripHexPrefix(storageProof.value)),
    // Account proof
    accountProofsConcat,
    accountProofsConcat.length,
    accountProofSizesWords,
    accountProofSizesWords.length,
    accountProofSizesBytes,
    accountProofSizesBytes.length,
    // Storage proof
    storageProofsConcat,
    storageProofsConcat.length,
    storageProofSizesWords,
    storageProofSizesWords.length,
    storageProofSizesBytes,
    storageProofSizesBytes.length,
  ];
}
