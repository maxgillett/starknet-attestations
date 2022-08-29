%builtins range_check bitwise

# TODO: Getting an error "Unexpected implicit argument 'pedersen_ptr' in an external function"
# unless we declare this as a Starknet contract. Doing so now prevents us from running locally
# using cairo-compile and cairo-run. Is the solution to pass pedersen_ptr (and any other implicit
# arguments) to every function in this module?
# %builtins range_check bitwise

# Keccak code from https://github.com/starkware-libs/cairo-examples/tree/master/keccak
from lib.keccak import keccak, finalize_keccak
from lib.bytes_utils import IntArray, swap_endian

# Storage verification code from https://github.com/OilerNetwork/fossil
from lib.storage_verification.keccak import keccak256
from lib.storage_verification.trie_proofs import verify_proof
from lib.storage_verification.extract_from_rlp import extract_data
from lib.storage_verification.types import IntsSequence, reconstruct_ints_sequence_list
from lib.storage_verification.swap_endianness import swap_endianness_four_words
from lib.storage_verification.comp_arr import arr_eq
from lib.storage_verification.concat_arr import concat_arr

# Secp code modified from https://github.com/starkware-libs/cairo-examples/tree/master/secp
from lib.secp.secp import ecdsa_raw_recover
from lib.secp.bigint import BigInt3

from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_lt,
    uint256_unsigned_div_rem,
    uint256_mul,
    uint256_add,
    split_64,
)
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import unsigned_div_rem

const ACCOUNT = 1
const STORAGE = 2

struct Signature:
    member message : IntArray
    member R_x : BigInt3
    member R_y : BigInt3
    member s : BigInt3
    member v : felt
end

struct StorageProof:
    member key : IntArray
    member value : IntArray
    member proof : IntsSequence*
end

struct Proof:
    member address : IntArray
    member state_root : IntArray
    member account_proof : IntsSequence*
    member account_proof_len : felt
    member balance : felt
    member code_hash : IntArray
    member nonce : felt
    member storage_slot : IntArray
    member storage_hash : IntArray
    member storage_proof : StorageProof
    member storage_proof_len : felt
    member signature : Signature
end

func keccak256_20{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(input_ptr : felt*) -> (
    trie_key : felt*
):
    alloc_locals
    let (local input : felt*) = alloc()
    let (local input0) = swap_endian(input_ptr[0], 8)
    assert input[0] = input0
    let (local input1) = swap_endian(input_ptr[1], 8)
    assert input[1] = input1
    let (local input2) = swap_endian(input_ptr[2], 4)
    assert input[2] = input2
    local bitwise_ptr_start : BitwiseBuiltin* = bitwise_ptr
    let (local keccak_ptr : felt*) = alloc()
    let keccak_ptr_start = keccak_ptr
    let (trie_key_le) = keccak{keccak_ptr=keccak_ptr}(input, 20)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)
    let (trie_key_be) = swap_endianness_four_words(IntsSequence(trie_key_le, 4, 32))
    return (trie_key_be.element)
end

# # Integer manipulation

func split{range_check_ptr}(a : Uint256) -> (res : BigInt3):
    alloc_locals
    local base : Uint256 = Uint256(low=2 ** 86, high=0)
    let (n0, d0) = uint256_unsigned_div_rem(a, base)
    let (n1, d1) = uint256_unsigned_div_rem(n0, base)
    let (_, d2) = uint256_unsigned_div_rem(n1, base)
    local res : BigInt3 = BigInt3(d0.low, d1.low, d2.low)
    return (res)
end

# TODO: Pack without using U256 as an intermediate representation
func pack_uint64{range_check_ptr}(n : BigInt3) -> (res : felt*):
    alloc_locals
    local base : Uint256 = Uint256(low=2 ** 86, high=0)
    let (base2, _) = uint256_mul(base, base)
    local a : Uint256 = Uint256(low=n.d0, high=0)
    let (b, _) = uint256_mul(Uint256(low=n.d1, high=0), base)
    let (c, _) = uint256_mul(Uint256(low=n.d2, high=0), base2)
    let (d, _) = uint256_add(a, b)
    let (e, _) = uint256_add(d, c)
    let (local res : felt*) = alloc()
    let (r0, r1) = split_64(e.low)
    let (r2, r3) = split_64(e.high)
    assert res[0] = r3
    assert res[1] = r2
    assert res[2] = r1
    assert res[3] = r0
    return (res)
end

func int_array_to_U256(a : felt*, word_len : felt) -> (res : Uint256):
    # TODO: Turn into recursive function
    if word_len == 1:
        return (Uint256(a[0], 0))
    end
    if word_len == 2:
        return (Uint256(a[1] + a[0] * 2 ** 64, 0))
    end
    return (Uint256(0, 0))
end

func int_array_to_address_felt(a : felt*) -> (res : felt):
    return (a[3] + a[2] * 2 ** 64 + a[1] * 2 ** 128 + a[0] * 2 ** 192)
end

# # Array manipulation

func to_ints_seq(int_array : IntArray) -> (res : IntsSequence):
    let res = IntsSequence(
        element=int_array.elements,
        element_size_words=int_array.word_len,
        element_size_bytes=int_array.byte_len,
    )
    return (res)
end

# Slice to four 64 bit words, beginning from start_pos
func slice_arr(array : felt*, start_pos : felt) -> (res : IntArray):
    # TODO:
    alloc_locals
    let (elements : felt*) = alloc()
    assert elements[0] = array[start_pos]
    assert elements[1] = array[start_pos + 1]
    assert elements[2] = array[start_pos + 2]
    assert elements[3] = array[start_pos + 3]
    local res : IntArray = IntArray(elements=elements, word_len=4, byte_len=32)
    return (res)
end

func extract_account{range_check_ptr}(rlp_data : IntsSequence) -> (
    nonce : felt, balance : felt, storage_root : IntsSequence, code_hash : IntsSequence
):
    alloc_locals
    let (local storage_root : IntsSequence) = extract_data(5, 32, rlp_data)
    let (local code_hash : IntsSequence) = extract_data(38, 32, rlp_data)
    return (1, 0, storage_root, code_hash)
end

func extract_message_contents(message : IntArray) -> (
    starknet_account : felt, storage_root : IntArray, storage_key : IntArray
):
    alloc_locals
    let (starknet_account) = int_array_to_address_felt(message.elements + 4)
    let (storage_root) = slice_arr(message.elements, 8)
    let (storage_key) = slice_arr(message.elements, 12)
    return (starknet_account, storage_root, storage_key)
end

func encode_kv_position{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
    slot : IntArray, address : IntArray
) -> (key : IntsSequence):
    alloc_locals
    let (input : felt*) = alloc()

    # Address
    assert input[0] = address.elements[0]
    assert input[1] = address.elements[1]
    assert input[2] = address.elements[2]
    assert input[3] = address.elements[3]

    # Storage slot
    assert input[4] = slot.elements[0]
    assert input[5] = slot.elements[1]
    assert input[6] = slot.elements[2]
    assert input[7] = slot.elements[3]

    let (local keccak_ptr : felt*) = alloc()
    let (out_le) = keccak256{keccak_ptr=keccak_ptr}(input, 64)
    let (key) = swap_endianness_four_words(IntsSequence(out_le, 4, 32))
    return (key)
end

func extract_verification_arguments(proof_ptr : Proof*, proof_type : felt) -> (
    root_hash : IntsSequence, proof : IntsSequence*, proof_len : felt
):
    alloc_locals
    if proof_type == ACCOUNT:
        let (root) = to_ints_seq(proof_ptr.state_root)
        local proof : IntsSequence* = proof_ptr.account_proof
        local len = proof_ptr.account_proof_len
        return (root, proof, len)
    end
    if proof_type == STORAGE:
        let (root) = to_ints_seq(proof_ptr.storage_hash)
        local proof : IntsSequence* = proof_ptr.storage_proof.proof
        local len = proof_ptr.storage_proof_len
        return (root, proof, len)
    end
    ret
end

func hash_eip191_message{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(message : IntArray) -> (
    msg_hash : BigInt3
):
    alloc_locals
    let (local keccak_ptr : felt*) = alloc()
    let (output_le) = keccak256{keccak_ptr=keccak_ptr}(message.elements, message.byte_len)
    let (output_be) = swap_endianness_four_words(IntsSequence(output_le, 4, 32))
    local output : felt* = output_be.element
    local output_uint : Uint256 = Uint256(
        low=output[2] * 2 ** 64 + output[3],
        high=output[0] * 2 ** 64 + output[1])
    let (msg_hash) = split(output_uint)
    return (msg_hash)
end

func recover_address{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
    msg_hash : BigInt3, R_x : BigInt3, R_y : BigInt3, s : BigInt3, v : felt
) -> (address : IntArray):
    alloc_locals
    let (public_key_ec) = ecdsa_raw_recover(msg_hash, R_x, R_y, s, v)
    let (elements_x) = pack_uint64(public_key_ec.x)
    let (elements_y) = pack_uint64(public_key_ec.y)
    let (elements_pubkey, _) = concat_arr(elements_x, 4, elements_y, 4)
    let (local keccak_ptr : felt*) = alloc()
    let (hash_le) = keccak256{keccak_ptr=keccak_ptr}(elements_pubkey, 64)
    let (hash_be) = swap_endianness_four_words(IntsSequence(hash_le, 4, 32))
    local hash : felt* = hash_be.element
    let (local elements : felt*) = alloc()
    assert elements[0] = 0
    let (masked) = bitwise_and(0x00000000ffffffff, hash[1])
    assert elements[1] = masked
    assert elements[2] = hash[2]
    assert elements[3] = hash[3]
    local address : IntArray = IntArray(elements, 4, 32)
    return (address)
end

func verify_account_proof{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(proof_ptr : Proof*):
    alloc_locals

    # Compute trie key
    let input_ptr : felt* = proof_ptr.address.elements
    let (elements) = keccak256_20(input_ptr)
    local path : IntsSequence = IntsSequence(elements, 4, 32)

    # Retrieve RLP encoded account data from proof
    let (root_hash, proof, proof_len) = extract_verification_arguments(proof_ptr, ACCOUNT)
    let (local account_data : IntsSequence) = verify_proof(path, root_hash, proof, proof_len)
    let (nonce, balance, storage_root, code_hash) = extract_account(account_data)

    # Compare derived hashes
    let (local storage_root_match : felt) = arr_eq(
        storage_root.element,
        storage_root.element_size_words,
        proof_ptr.storage_hash.elements,
        proof_ptr.storage_hash.word_len,
    )
    let (local code_hash_match : felt) = arr_eq(
        code_hash.element,
        code_hash.element_size_words,
        proof_ptr.code_hash.elements,
        proof_ptr.code_hash.word_len,
    )
    assert storage_root_match = 1
    assert code_hash_match = 1

    return ()
end

func verify_storage_proof{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
    proof_ptr : Proof*,
    starknet_address : felt,
    ethereum_address : IntArray,
    token_balance_min : Uint256,
):
    alloc_locals

    # TODO: include storage_hash in signed message contents
    # Extract Starknet account address, storage root, and storage key from signed message contents
    let message = proof_ptr.signature.message
    let (starknet_account, state_root, storage_key) = extract_message_contents(message)

    # Verify starknet address in signed message
    assert starknet_account = starknet_address

    # Verify that signed storage key matches derived trie key
    let storage_slot = proof_ptr.storage_slot
    let (path) = encode_kv_position(storage_slot, ethereum_address)

    # Compare trie path to signed storage key
    let (local storage_key_match : felt) = arr_eq(
        path.element, path.element_size_words, storage_key.elements, storage_key.word_len
    )
    assert storage_key_match = 1

    # Retrieve RLP encoded storage value from proof
    let (root_hash, proof, proof_len) = extract_verification_arguments(proof_ptr, STORAGE)
    let (local keccak_ptr : felt*) = alloc()
    let (path_hash_le) = keccak256{keccak_ptr=keccak_ptr}(path.element, 32)
    let (path_hash_be) = swap_endianness_four_words(IntsSequence(path_hash_le, 4, 32))
    let (local storage_value : IntsSequence) = verify_proof(
        path_hash_be, root_hash, proof, proof_len
    )

    # # TODO: Compare root hash to signed storage hash
    # let (local storage_hash_match: felt) = arr_eq(
    #    root_hash.element, root_hash.element_size_words,
    #    storage_hash.elements, storage_hash.word_len)
    # assert storage_hash_match = 1

    # Check that balance in storage > minimum
    let (balance) = int_array_to_U256(storage_value.element, storage_value.element_size_words)
    let (is_lt : felt) = uint256_lt(token_balance_min, balance)
    assert is_lt = 1

    return ()
end

# # Proof encoding / decoding

func reconstruct_big_int3(input : felt*) -> (res : BigInt3):
    tempvar res = BigInt3(input[0], input[1], input[2])
    return (res)
end

func encode_proof{range_check_ptr}(
    balance : felt,
    nonce : felt,
    account_proof_len : felt,
    storage_proof_len : felt,
    address_ : felt*,
    state_root_ : felt*,
    code_hash_ : felt*,
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
) -> (proof : Proof*):
    alloc_locals

    # Reconstruct IntArray
    tempvar address = IntArray(address_, 3, 20)
    tempvar state_root = IntArray(state_root_, 4, 32)
    tempvar code_hash = IntArray(code_hash_, 4, 32)
    tempvar storage_slot = IntArray(storage_slot_, 4, 32)
    tempvar storage_hash = IntArray(storage_hash_, 4, 32)
    tempvar message = IntArray(message_, message_len, message_byte_len)
    tempvar storage_key = IntArray(storage_key_, 4, 32)
    tempvar storage_value = IntArray(storage_value_, 4, 32)

    # Reconstruct BigInt3
    let (R_x) = reconstruct_big_int3(R_x_)
    let (R_y) = reconstruct_big_int3(R_y_)
    let (s) = reconstruct_big_int3(s_)

    # Reconstruct IntsSequence*
    let (local account_proof_arg : IntsSequence*) = alloc()
    let (local storage_proof_arg : IntsSequence*) = alloc()
    reconstruct_ints_sequence_list(
        account_proofs_concat,
        account_proofs_concat_len,
        account_proof_sizes_words,
        account_proof_sizes_words_len,
        account_proof_sizes_bytes,
        account_proof_sizes_bytes_len,
        account_proof_arg,
        0,
        0,
        0,
    )
    reconstruct_ints_sequence_list(
        storage_proofs_concat,
        storage_proofs_concat_len,
        storage_proof_sizes_words,
        storage_proof_sizes_words_len,
        storage_proof_sizes_bytes,
        storage_proof_sizes_bytes_len,
        storage_proof_arg,
        0,
        0,
        0,
    )

    local storage_proof : StorageProof = StorageProof(
        key=storage_key, value=storage_value, proof=storage_proof_arg)
    local signature : Signature = Signature(
        message=message, R_x=R_x, R_y=R_y, s=s, v=v)
    local proof : Proof = Proof(
        address=address,
        state_root=state_root,
        account_proof=account_proof_arg,
        account_proof_len=account_proof_len,
        balance=balance,
        code_hash=code_hash,
        nonce=nonce,
        storage_slot=storage_slot,
        storage_hash=storage_hash,
        storage_proof=storage_proof,
        storage_proof_len=storage_proof_len,
        signature=signature)

    let (__fp__, _) = get_fp_and_pc()
    return (proof=&proof)
end

func encode_proof_from_json() -> (proof : Proof*):
    alloc_locals

    local balance : felt
    local nonce : felt
    local account_proof_len : felt
    local storage_proof_len : felt

    local address : IntArray
    local state_root : IntArray
    local code_hash : IntArray
    local storage_slot : IntArray
    local storage_hash : IntArray

    local message : IntArray
    local R_x : BigInt3
    local R_y : BigInt3
    local s : BigInt3
    local v : felt

    let (account_proof : IntsSequence*) = alloc()
    let (storage_proof0 : IntsSequence*) = alloc()

    local storage_key : IntArray
    local storage_value : IntArray

    %{
        from math import ceil
        from starkware.cairo.common.cairo_secp.secp_utils import split

        # TODO: Combine usage of IntArray and IntsSequence into single data struct
        def pack_intarray(base_addr, hex_input):
            elements = segments.add()
            for j in range(0, len(hex_input) // 16 + 1):
                hex_str = hex_input[j*16 : (j+1) * 16]
                if len(hex_str) > 0:
                    memory[elements + j] = int(hex_str, 16)
            memory[base_addr + ids.IntArray.elements] = elements
            memory[base_addr + ids.IntArray.word_len] = int(ceil(len(hex_input) / 2. / 8))
            memory[base_addr + ids.IntArray.byte_len] = int(len(hex_input) / 2)

        def pack_bigint3(base_addr, input):
            d0, d1, d2 = split(input)
            memory[base_addr + ids.BigInt3.d0] = d0
            memory[base_addr + ids.BigInt3.d1] = d1
            memory[base_addr + ids.BigInt3.d2] = d2

        ids.balance = program_input['balance']
        ids.nonce = program_input['nonce']
        ids.account_proof_len = len(program_input['accountProof'])
        ids.storage_proof_len = len(program_input['storageProof'][0]['proof'])

        pack_intarray(ids.address.address_, program_input['address'][2:])
        pack_intarray(ids.state_root.address_, program_input['stateRoot'][2:])
        pack_intarray(ids.code_hash.address_, program_input['codeHash'][2:])
        pack_intarray(ids.storage_slot.address_, program_input['storageSlot'][2:])
        pack_intarray(ids.storage_hash.address_, program_input['storageHash'][2:])
        pack_intarray(ids.storage_key.address_, program_input['storageProof'][0]['key'][2:])
        pack_intarray(ids.storage_value.address_, program_input['storageProof'][0]['value'][2:])

        # Account proof
        for i, proof in enumerate(program_input['accountProof']):
            base_addr = ids.account_proof.address_ + ids.IntsSequence.SIZE * i
            pack_intarray(base_addr, proof[2:])

        # Storage proof (TODO: add support for more than one proof)
        for i, proof in enumerate(program_input['storageProof'][0]['proof']):
            base_addr = ids.storage_proof0.address_ + ids.IntsSequence.SIZE * i
            pack_intarray(base_addr, proof[2:])

        # Signature
        pack_intarray(ids.message.address_, program_input['signature']['message'][2:])
        pack_bigint3(ids.R_x.address_, program_input['signature']['R_x'])
        pack_bigint3(ids.R_y.address_, program_input['signature']['R_y'])
        pack_bigint3(ids.s.address_, program_input['signature']['s'])
        ids.v = program_input['signature']['v']
    %}

    local storage_proof : StorageProof = StorageProof(
        key=storage_key, value=storage_value, proof=storage_proof0)
    local signature : Signature = Signature(
        message=message, R_x=R_x, R_y=R_y, s=s, v=v)
    local proof : Proof = Proof(
        address=address,
        state_root=state_root,
        account_proof=account_proof,
        account_proof_len=account_proof_len,
        balance=balance,
        code_hash=code_hash,
        nonce=nonce,
        storage_slot=storage_slot,
        storage_hash=storage_hash,
        storage_proof=storage_proof,
        storage_proof_len=storage_proof_len,
        signature=signature)

    let (__fp__, _) = get_fp_and_pc()
    return (proof=&proof)
end

func main{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}():
    alloc_locals
    let (local proof : Proof*) = encode_proof_from_json()

    # Extract Ethereum account address from signed message hash and signature
    let message = proof.signature.message
    let R_x = proof.signature.R_x
    let R_y = proof.signature.R_y
    let s = proof.signature.s
    let v = proof.signature.v
    let (msg_hash) = hash_eip191_message(message)
    let (ethereum_address) = recover_address(msg_hash, R_x, R_y, s, v)

    let (__fp__, _) = get_fp_and_pc()

    # TODO: Don't use hardcoded starknet address: derive it from the from message contents
    verify_storage_proof(
        proof_ptr=proof,
        starknet_address=1957663644354712299057139143307800152203267791838595301767954663167657192466,
        ethereum_address=ethereum_address,
        token_balance_min=Uint256(1, 0),
    )
    verify_account_proof(proof_ptr=proof)

    let eth_account = ethereum_address.elements[1] * 2 ** (86 * 2) +
        ethereum_address.elements[2] * 2 ** 86 +
        ethereum_address.elements[3]
    assert eth_account = 443622735761256760265574472945318887371472666514

    ret
end
