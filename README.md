### Overview

This proof of concept project enables users to generate non-transferable attestations for specific EVM state ("badges") and link them to their Starknet account. At the moment these attestations are limited to simple statements about one's token balance, but can easily be extended to more complex attestations, such as a deposit to a staking contract or a liquidation event. Token badges could be used for vanity, to trustlessly gate community chats, or as an alternative means for airdrop distribution (instead of manually constructing Merkle trees of eligible users). 

Verification of both the account and storage proofs takes approximately 1.5-2m steps, depending on proof size, and exceeds the currently imposed Starknet step size limits (250k and 1m for testnet and mainnet, respectively). It is not possible to verify a storage proof alone, as a dishonest attestation submitter can use a storage trie hash corresponding to a different token contract than the one in question. Optimizations may be able to bring the step count beneath the current mainnet limit.

### Running locally

The web application can be started on `localhost:3000` by running `yarn start` after installing dependencies. Due to the step count limit, transactions sent to the deployed contract on testnet will fail (see above).

To run the Cairo contract locally, first run `python scripts/generate_proof.py` to construct the desired token balance proof and signed message, and then execute the `cairo_compile_and_run.sh` script.

### Adding privacy

Privacy can be achieved by using an offline mechanism to check the computational integrity of a specific state verification, revealing only select details, and posting this proof on chain. One approach is to construct a zk-SNARK or zk-STARK that hides sensitive information in the private witnesses of the proof, and to use a verifier deployed on Starknet to check its correctness. Progress has been made in the design of zk-SNARK circuits that could achieve this task. Two of the key primitives underlying the attestation logic ([Keccak-256](https://github.com/vocdoni/keccak256-circom) and [ECDSA signature verification](https://github.com/0xPARC/circom-ecdsa)) have been implemented in Circom. Unfortunately, these circuits involve a significant number of constraints, which makes working with SNARKs cumbersome. Specifically, while verification of these proofs is cheap, their generation can impose a significant barrier for the average user, requiring access to a machine with large amounts of RAM and possession of a proving key in excess of 4GB.

A potentially more promising route involves turning to zk-STARKS. By writing a zk-STARK verifier in Cairo and deploying it on Starknet (L2), one can generate an offline zero knowledge proof of the relevant state verification (reusing the Cairo code in this project) that is then submitted to and verified on L2. A couple options exist regarding the prover. While the Starkware prover is currently closed source, there are plans to open source it under the [Polaris License](https://starkware.co/starkware-polaris-prover-license/), where with the permission of the community it could be targeted to Starknet and altered to enable zero knowledge. Another option is to build a prover from scratch, potentially building upon [Winterfell](https://github.com/novifinancial/winterfell).

An intermediate form of privacy could also be achieved by constructing anonymity sets for designated types of state attestations, similar to how Tornado Cash effectively mixes together ETH/token deposits of a fixed size.  Instead of providing account and storage proof alongside a proposed Starknet address, the user can instead supply a cryptographic commitment to that address which is added to a shared Merkle tree. The user can choose to reveal their commitment and thereby claim the proof at a later time. Unfortunately, to receive any privacy benefits from this design the user must wait to claim until the anonymity pool is sufficiently large. This can be problematic when the fungibility of the state in question is intrinsically small (e.g. a small collection of NFTs) or when there is a lack of interest around the state in question (e.g. proving ownership of an obscure but highly fungible token). 

### Acknowledgements

The L1 state verification library is derived from the [fossil](https://github.com/OilerNetwork/fossil) library built by @marcellobardus and team at OilerNetwork.

The [Cairo secp256k1 library](https://github.com/starkware-libs/cairo-examples) was built by @liorgold2 and team at Starkware.

The React webapp is based on the [example app](https://github.com/fracek/starknet-react-example) developed by @fracek and team at Auclantis.
