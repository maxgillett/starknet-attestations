import React from "react";
import type { Web3ReactHooks } from '@web3-react/core'
import type { MetaMask } from '@web3-react/metamask'
import { Network } from '@web3-react/network'
import { useState } from 'react'
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
              : connector.activate(desiredChainId === -1 ? undefined : desiredChainId)
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
                    : connector.activate(desiredChainId === -1 ? undefined : desiredChainId)
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
