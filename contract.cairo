from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256

from verify_proof import Proof, encode_proof, verify_account_proof, verify_storage_proof, hash_eip191_message, recover_address, reconstruct_big_int3

from lib.bytes_utils import IntArray
from lib.secp.bigint import BigInt3


@event
func mint_called(
    token: felt,
    eth_account: felt,
    chain_id: felt,
    block_number: felt,
    state_root_lo: felt,
    storage_hash_lo: felt,
    balance: felt,
    starknet_account: felt):
end

@storage_var
func badges(
    token: felt,
    eth_account: felt,
    chain_id: felt,
    block_number: felt,
    state_root_lo: felt,
    storage_hash_lo: felt,
    balance: felt) -> (starknet_account: felt):
end

@external
func mint{
        syscall_ptr : felt*,
        range_check_ptr,
        pedersen_ptr: HashBuiltin*,
        bitwise_ptr: BitwiseBuiltin*}(
    starknet_account : felt,
    token_balance_min : felt,
    chain_id : felt,
    block_number : felt,
    account_proof_len : felt,
    storage_proof_len : felt,
    address__len : felt,
    address_ : felt*,
    state_root__len : felt,
    state_root_ : felt*,
    code_hash__len : felt,
    code_hash_ : felt*,
    storage_slot__len : felt,
    storage_slot_ : felt*,
    storage_hash__len : felt,
    storage_hash_ : felt*,
    message__len : felt,
    message_ : felt*,
    message_byte_len : felt,
    R_x__len : felt,
    R_x_ : felt*,
    R_y__len : felt,
    R_y_ : felt*,
    s__len : felt,
    s_ : felt*,
    v : felt,
    storage_key__len : felt,
    storage_key_ : felt*,
    storage_value__len : felt,
    storage_value_ : felt*,
    account_proofs_concat_len : felt,
    account_proofs_concat : felt*,
    account_proof_sizes_words_len : felt,
    account_proof_sizes_words : felt*,
    account_proof_sizes_bytes_len : felt,
    account_proof_sizes_bytes : felt*,    
    storage_proofs_concat_len : felt,
    storage_proofs_concat : felt*,
    storage_proof_sizes_words_len : felt,
    storage_proof_sizes_words : felt*,
    storage_proof_sizes_bytes_len : felt,
    storage_proof_sizes_bytes : felt*,
):
    alloc_locals

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
        message__len,
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

    # Verify proofs, starknet and ethereum address, and min balance (TODO: Pass state_root 
    # and storage_hash so that they too can be verified from the signed message)
    verify_storage_proof(proof, starknet_account, ethereum_address, Uint256(token_balance_min, 0))
    verify_account_proof(proof)

    # Write new badge entry in map
    let token = address_[1] * 2**(86*2) + 
                address_[2] * 2**86 + 
                address_[3]
    let eth_account = ethereum_address.elements[1] * 2**(86*2) + 
                      ethereum_address.elements[2] * 2**86 + 
                      ethereum_address.elements[3]
    let state_root_lo = state_root_[2] * 2**86 + 
                        state_root_[3]
    let storage_hash_lo = storage_hash_[2] * 2**86 + 
                          storage_hash_[3]
    badges.write(
        token,
        eth_account,
        chain_id,
        block_number,
        state_root_lo,
        storage_hash_lo,
        token_balance_min,
        starknet_account)

    mint_called.emit(
        token,
        eth_account,
        chain_id,
        block_number,
        state_root_lo,
        storage_hash_lo,
        token_balance_min,
        starknet_account)

    return ()
end
