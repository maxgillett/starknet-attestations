import React from "react";
import { useStarknet } from "../../providers/StarknetProvider";

//import styles from "./index.module.css";

interface StarknetConnectedOnlyProps {
  children: React.ReactNode;
}

export default function StarknetWallet(): JSX.Element {
  const { account, connectBrowserWallet } = useStarknet();

  if (!account) {
    return (
      <div>
        <button
          onClick={() => connectBrowserWallet()}
        >
          Connect Wallet (Starknet)
        </button>
      </div>
    );
  } else {
    return (
      <div>
        <button>
          Disconnect Wallet (Starknet)
        </button>
      </div>
    );
  }
}

//export function StarknetConnected({ children }: StarknetConnectedOnlyProps): JSX.Element {
//  const { account, connectBrowserWallet } = useStarknet();
//
//  if (account) {
//    return (
//      <div>
//      <React.Fragment>{children}</React.Fragment>
//      </div>
//    );
//  } else {
//    return (
//      <div>
//      </div>
//    );
//  }
//}
