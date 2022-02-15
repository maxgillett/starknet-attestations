import React from "react"
import { MintBadge } from "../../components/Minter/Minter"
import { useMinterContract } from "../../lib/minter";

const MintPage = () => {
    const minterContract = useMinterContract();

    return (
      <div>
        <MintBadge contract={minterContract} />
      </div>
    )
}

export default MintPage;
