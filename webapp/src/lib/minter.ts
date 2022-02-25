import React from "react";
import { Contract, Abi } from "starknet";
import { useStarknet } from "../providers/StarknetProvider";
import { sha3Raw, stripHexPrefix, toHex, padLeft, toBN } from "web3-utils"
import { utils } from "ethers"
import { secp256k1 } from "@zoltu/ethereum-crypto"
import * as BN from "bn.js";

import MINTER from "./abi/minter.json";

const ADDRESS =
  "0x0411fd5f3e4916e02083304d4983c42d10d96027816609f7b77a5f3b3e1958c0";

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
    flatProofSizesWords,
    flatProofSizesBytes,
  ]
}

// Encode call arguments for the "mint" method of the Minter contract
export async function encodeCallArgs(
  provider: any,
  chainId: number,
  ethAccount: string,
  starknetAccount_: string,
  token: string,
  blockNumber: number,
  storageSlot: string,
  balance: string,
) {
  const number = "0x"+blockNumber.toString(16)
  const block = await provider?.send("eth_getBlockByNumber", [number, false]);

  // Prepare message attestation contents
  let pos = padLeft(stripHexPrefix(ethAccount.toLowerCase()), 64)
  pos += padLeft(stripHexPrefix(toHex(storageSlot)), 64)
  const storageKey = sha3Raw("0x"+pos)
  const starknetAccount = stripHexPrefix(starknetAccount_);
  const stateRoot = stripHexPrefix(block.stateRoot);

  // Sign attestation message
  const message = starknetAccount + stateRoot + stripHexPrefix(storageKey);
  const paddedMessage = "000000" + message + "00000000";
  let packedMessage : Array<BN> = [
    toBN("1820989616068650357"),
    toBN("7863376661560845668"),
    toBN("2327628128951822181"),
    toBN("4182209287050756096")];
  packedMessage.push(...packInts64(paddedMessage));
  const rawSignature = await provider?.getSigner().signMessage(paddedMessage);
  const signature = utils.splitSignature(rawSignature);

  // Derive the y-coordinate of the elliptic curve point
  const Rx = BigInt("0x"+toBN(signature.r).toJSON());
  const recoveryParam : 0|1 = signature.recoveryParam === 0 ? 0 : 1;
  const Ry = secp256k1.decompressPoint(Rx, recoveryParam);
  console.log("Rx", Rx);
  console.log("Ry", Ry);

  // Request storage state proof
  const proof = await provider?.send("eth_getProof", [
      token, 
      [storageKey], 
      number]);
  const accountProof = proof.accountProof;
  const storageProof = proof.storageProof[0];
  const [
    accountProofsConcat,
    accountProofSizesWords,
    accountProofSizesBytes] = encodeProof(accountProof);
  const [
    storageProofsConcat,
    storageProofSizesWords,
    storageProofSizesBytes] = encodeProof(storageProof.proof);
  console.log(proof);

  console.log(toBN(starknetAccount_))
  console.log(toBN(balance))
  console.log(1) // chain id
  console.log(blockNumber) 
  console.log(accountProof.length)
  console.log(storageProof.proof.length)
  console.log(packInts64(stripHexPrefix(token))) // address
  console.log(packInts64(stripHexPrefix(block.stateRoot)))
  console.log(packInts64(stripHexPrefix(proof.codeHash)))
  console.log(packInts64(padLeft(stripHexPrefix(toHex(storageSlot)), 64)))
  console.log(packBigInt3(stripHexPrefix(proof.storageHash)))
  // Signed state signature
  console.log(packedMessage)
  console.log(132) // message_byte_len
  console.log(packBigInt3(stripHexPrefix(Rx.toString())))
  console.log(packBigInt3(stripHexPrefix(Ry.toString())))
  console.log(packBigInt3(stripHexPrefix(signature.s)))
  console.log(signature.recoveryParam + 27)
  console.log(packInts64(stripHexPrefix(storageProof.key)))
  console.log(packInts64(stripHexPrefix(storageProof.value)))
  // Account proof
  console.log(accountProofsConcat)
  console.log(accountProofSizesWords)
  console.log(accountProofSizesBytes)
  // Storage proof
  console.log(storageProofsConcat)
  console.log(storageProofSizesWords)
  console.log(storageProofSizesBytes)
  
  return [
    toBN(starknetAccount_),
    toBN(balance),
    1, // chain id
    blockNumber, 
    accountProof.length,
    storageProof.proof.length,
    packInts64(stripHexPrefix(token)), // address
    packInts64(stripHexPrefix(block.stateRoot)),
    packInts64(stripHexPrefix(proof.codeHash)),
    packInts64(padLeft(stripHexPrefix(toHex(storageSlot)), 64)),
    packBigInt3(stripHexPrefix(proof.storageHash)),
    // Signed state signature
    packedMessage,
    132, // message_byte_len
    packBigInt3(stripHexPrefix(Rx.toString())),
    packBigInt3(stripHexPrefix(Ry.toString())),
    packBigInt3(stripHexPrefix(signature.s)),
    signature.recoveryParam + 27,
    packInts64(stripHexPrefix(storageProof.key)),
    packInts64(stripHexPrefix(storageProof.value)),
    // Account proof
    accountProofsConcat,
    accountProofSizesWords,
    accountProofSizesBytes,
    // Storage proof
    storageProofsConcat,
    storageProofSizesWords,
    storageProofSizesBytes,
  ];
}
