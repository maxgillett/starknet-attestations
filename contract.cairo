%lang starknet

from verify_proof import encode_proof, verify_account_proof, verify_storage_proof, hash_eip191_message, recover_address

@storage_var
func badges(token: felt, eth_account: felt, chain_id: felt, balance: felt) -> (starknet_account: felt):
end

@external
func mint(
    starknet_account : felt,
    token_balance_min : felt,
    account_proof_len : felt,
    storage_proof_len : felt,
    address_ : felt*,
    state_root_ : felt* ,
    code_hash_ : felt* ,
    storage_slot_ : felt*,
    storage_hash_ : felt*,
    message_ : felt*,
    message_len : felt,
    message_byte_len : felt,
    R_x_ : felt*,
    R_y_ : felt*,
    s_ : felt*,
    v : felt,
    storage_key_ : felt*,
    storage_value_ : felt*,
    account_proofs_concat : felt*,
    account_proofs_concat_len : felt,
    account_proof_sizes_words : felt*,
    account_proof_sizes_words_len : felt,
    account_proof_sizes_bytes : felt*,
    account_proof_sizes_bytes_len : felt,
    storage_proofs_concat : felt*,
    storage_proofs_concat_len : felt,
    storage_proof_sizes_words : felt*,
    storage_proof_sizes_words_len : felt,
    storage_proof_sizes_bytes : felt*,
    storage_proof_sizes_bytes_len : felt,
):

    let (local proof: Proof*) = encode_proof(
        0, # balance,
        1, # nonce,
        account_proof_len,
        storage_proof_len,
        address_,
        state_root_,
        code_hash_,
        storage_slot_,
        storage_hash_,
        message_,
        message_len,
        message_byte_len,
        R_x_,
        R_y_,
        s_,
        v,
        storage_key_,
        storage_value_,
        account_proofs_concat,
        account_proofs_concat_len,
        account_proof_sizes_words,
        account_proof_sizes_words_len,
        account_proof_sizes_bytes,
        account_proof_sizes_bytes_len,
        storage_proofs_concat,
        storage_proofs_concat_len,
        storage_proof_sizes_words,
        storage_proof_sizes_words_len,
        storage_proof_sizes_bytes,
        storage_proof_sizes_bytes_len) 

    # Extract Ethereum account address from signed message hash and signature
    let message = proof.signature.message
    let R_x = proof.signature.R_x
    let R_y = proof.signature.R_y
    let s = proof.signature.s
    let v = proof.signature.v
    let (msg_hash) = hash_eip191_message(message)
    let (ethereum_address) = recover_address(msg_hash, R_x, R_y, s, v)

    verify_storage_proof(proof, ethereum_address, token_balance_min)
    verify_account_proof(proof)

    let eth_account = ethereum_address[1] * 2**(86*2) + 
                      ethereum_address[2] * 2**86 + 
                      ethereum_address[3]
    badges.write(token, eth_account, chain_id, token_balance_min, starknet_account)
end
