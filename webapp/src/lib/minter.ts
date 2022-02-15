import React from "react";
import { Contract, Abi } from "starknet";
import { useStarknet } from "../providers/StarknetProvider";

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

function splitInts() {
    // TODO
}

export async function encodeCallArgs(
  provider: any,
  eth_account: any,
  starknet_account: any,
  token: String,
  blockNumber: number,
  storageSlot: String,
  balance: String,
) {
  // TODO: Get state root
  // Request proof
  const proof = await provider?.send("eth_getProof", [
      eth_account, 
      ["1000000000000000000000000000000000000000000000000000000000000001"], 
      "0x"+blockNumber.toString(16)]);
  console.log(proof);
  // TODO: Sign attestation message
  const message = "TODO";
  const signature = await provider?.getSigner().signMessage(message);
  // TODO: Encode signature
  // TODO: Encode account proof 
  // TODO: Encode storage proof
  return [0, 1, 2];
}
