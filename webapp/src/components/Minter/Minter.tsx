import React from "react";
import { Contract } from "starknet";
import { useStarknetInvoke } from "../../lib/hooks";
import { encodeCallArgs } from "../../lib/minter";
import { useStarknet } from "../../providers/StarknetProvider";
import { useTransaction } from "../../providers/TransactionsProvider";
import { VoyagerLink } from "../VoyagerLink/VoyagerLink";
import { hooks, metaMask } from '../../connectors/metaMask'

const { useChainId, useAccounts, useError, useIsActivating, useIsActive, useProvider, useENSNames } = hooks


export function MintBadge({ contract }: { contract?: Contract }) {
  const { account } = useStarknet();
  const {
    invoke: mintBadge,
    hash,
    submitting,
  } = useStarknetInvoke(contract, "incrementCounter");
  const transactionStatus = useTransaction(hash);

  const accounts = useAccounts()
  const provider = useProvider();
  const isActive = useIsActive()

  const [token, setToken] = React.useState("0xc18360217d8f7ab5e7c516566761ea12ce7f9d72");
  const [blockNumber, setBlockNumber] = React.useState(14208200);
  const [storageSlot, setStorageSlot] = React.useState("0");
  const [balance, setBalance] = React.useState("1");

  const updateToken = React.useCallback(
    (evt: React.ChangeEvent<HTMLInputElement>) => {
      setToken(evt.target.value);
    },
    [setToken]
  );
  const updateBlockNumber = React.useCallback(
    (evt: React.ChangeEvent<HTMLInputElement>) => {
      setBlockNumber(Number(evt.target.value));
    },
    [setBlockNumber]
  );
  const updateStorageSlot = React.useCallback(
    (evt: React.ChangeEvent<HTMLInputElement>) => {
      setStorageSlot(evt.target.value);
    },
    [setStorageSlot]
  );
  const updateBalance = React.useCallback(
    (evt: React.ChangeEvent<HTMLInputElement>) => {
      setBalance(evt.target.value);
    },
    [setBalance]
  );

  if (!account) return (
    <div>
      Connect Starknet wallet to continue
    </div>
  );
  if (!isActive) return (
    <div>
      Connect Ethereum wallet to continue
    </div>
  );

  return (
    <div>
      <div className="row">
        <div>
          Owner: {accounts![0]}
        </div>
        <div>
          Token: <input onChange={updateToken} value={token} type="text" />
        </div>
        <div>
          Block: <input onChange={updateBlockNumber} value={blockNumber} type="number" />
        </div>
        <div>
          Storage slot: <input onChange={updateStorageSlot} value={storageSlot} type="text" />
        </div>
        <div>
          Balance: <input onChange={updateBalance} value={balance} type="text" />
        </div>
        <button
          onClick={ () => 
            mintBadge && 
            encodeCallArgs(
              provider,
              accounts![0],
              account,
              token,
              blockNumber,
              storageSlot,
              balance).then((res) => 
                { mintBadge(res) })}
          disabled={!mintBadge || submitting}
        >
          Mint Badge
        </button>
      </div>
      {transactionStatus && hash && (
        <div className="row">
          <h2>Latest Transaction</h2>
          <p>Status: {transactionStatus?.code}</p>
          <p>
            Hash: <VoyagerLink.Transaction transactionHash={hash} />
          </p>
        </div>
      )}
    </div>
  );
}
