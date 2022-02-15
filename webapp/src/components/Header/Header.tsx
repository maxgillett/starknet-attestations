import React from "react"
import {
    BrowserRouter as Router,
    Link,
} from "react-router-dom";
import EthereumWallet from "../Wallet/Ethereum";
import StarknetWallet from "../Wallet/Starknet";

const Header = () => {
    return (
      <div>
        <StarknetWallet />
        <EthereumWallet />
        <nav>
          <ul>
            <li>
              <Link to="/">Home</Link>
            </li>
            <li>
              <Link to="/mint">Mint</Link>
            </li>
            <li>
              <Link to="/view_badges">Badges</Link>
            </li>
          </ul>
        </nav>
      </div>
    )
}

export default Header;
