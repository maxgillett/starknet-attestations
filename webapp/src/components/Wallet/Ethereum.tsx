import React from "react";
import type { Web3ReactHooks } from '@web3-react/core'
import type { MetaMask } from '@web3-react/metamask'
import { Network } from '@web3-react/network'
import { useState } from 'react'
import { getAddChainParameters } from '../../chains'
import { hooks, metaMask } from '../../connectors/metaMask'

const { useChainId, useAccounts, useError, useIsActivating, useIsActive, useProvider, useENSNames } = hooks

export function Connect({
  connector,
  chainId,
  isActivating,
  error,
  isActive,
}: {
  connector: MetaMask | Network
  chainId: ReturnType<Web3ReactHooks['useChainId']>
  isActivating: ReturnType<Web3ReactHooks['useIsActivating']>
  error: ReturnType<Web3ReactHooks['useError']>
  isActive: ReturnType<Web3ReactHooks['useIsActive']>
}) {
  const isNetwork = connector instanceof Network

  const [desiredChainId, setDesiredChainId] = useState<number>(isNetwork ? 1 : -1)

  if (error) {
    return (
      <div>
        <button
          onClick={() =>
            connector instanceof Network
              ? connector.activate(desiredChainId === -1 ? undefined : desiredChainId)
              : connector.activate(desiredChainId === -1 ? undefined : getAddChainParameters(desiredChainId))
          }
        >
          Try Again?
        </button>
      </div>
    )
  } else if (isActive) {
    return (
      <div>
        <button onClick={() => connector.deactivate()}>Disconnect Wallet (Ethereum)</button>
      </div>
    )
  } else {
    return (
      <div>
        <button
          onClick={
            isActivating
              ? undefined
              : () =>
                  connector instanceof Network
                    ? connector.activate(desiredChainId === -1 ? undefined : desiredChainId)
                    : connector.activate(desiredChainId === -1 ? undefined : getAddChainParameters(desiredChainId))
          }
          disabled={isActivating}
        >
          Connect Wallet (Ethereum)
        </button>
      </div>
    )
  }
}

export default function EthereumWallet(): JSX.Element {
  const chainId = useChainId()
  const error = useError()
  const isActivating = useIsActivating()
  const isActive = useIsActive()

  return (
    <div>
      <Connect
        connector={metaMask}
        chainId={chainId}
        isActivating={isActivating}
        error={error}
        isActive={isActive}
      />
    </div>
  )
}

//interface StarknetConnectedOnlyProps {
//  children: React.ReactNode;
//}


//export function EthereumConnected({ children }: StarknetConnectedOnlyProps): JSX.Element {
//  const error = useError()
//  const isActive = useIsActive()
//  const provider = useProvider()
//
//  if (error) {
//    return (
//      <div>
//      Error connecting to Ethereum wallet
//      </div>
//    )
//  } else if (isActive) {
//    return (
//      <div>
//      <React.Fragment>{children}</React.Fragment>
//      </div>
//    )
//  } else {
//    return (
//      <div>
//      </div>
//    )
//  }
//}

//function signMessage(
//  provider: any,
//  contract: any,
//  storageSlot: any
//): undefined {
//  const signature = provider?.getSigner().signMessage('Message');
//  console.log(contract, storageSlot, signature);
//  return undefined;
//}


//export function SignEthereumMessage(): JSX.Element {
//  const error = useError()
//  const accounts = useAccounts()
//  const isActive = useIsActive()
//  const provider = useProvider()
//
//  const [contract, setContract] = React.useState("0x0");
//  const [storageSlot, setStorageSlot] = React.useState("0");
//
//  const updateContract = React.useCallback(
//    (evt: React.ChangeEvent<HTMLInputElement>) => {
//      setContract(evt.target.value);
//    },
//    [setContract]
//  );
//
//  const updateStorageSlot = React.useCallback(
//    (evt: React.ChangeEvent<HTMLInputElement>) => {
//      setStorageSlot(evt.target.value);
//    },
//    [setStorageSlot]
//  );
//
//  if (error) {
//    return (
//      <div>
//      Error
//      </div>
//    )
//  } else if (isActive) {
//    return (
//      <div>
//        <div>
//          Signing with Ethereum wallet: {accounts && accounts.length === 0
//            ? 'None'
//            : accounts }
//        </div>
//        <div>
//          Contract: <input onChange={updateContract} value={contract} type="text" />
//        </div>
//        <div>
//          Storage slot: <input onChange={updateStorageSlot} value={storageSlot} type="text" />
//        </div>
//        <button
//          onClick={() => signMessage(provider, { contract }, { storageSlot })}
//        >
//          Sign message
//        </button>
//      </div>
//    )
//  } else {
//    return (
//      <div>
//      </div>
//    )
//  }
//}
