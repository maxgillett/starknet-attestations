%builtins output range_check bitwise

from lib.keccak import keccak, finalize_keccak
from lib.bytes_utils import slice, IntArray, swap_endian

from lib.storage_verification.keccak import keccak256
from lib.storage_verification.trie_proofs import verify_proof
from lib.storage_verification.extract_from_rlp import extract_data
from lib.storage_verification.types import IntsSequence

from lib.secp.secp import ecdsa_raw_recover
from lib.secp.bigint import BigInt3

from starkware.cairo.common.uint256 import Uint256, uint256_lt
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

const ACCOUNT = 1
const STORAGE = 2

struct Signature:
    member message: IntArray
    member R_x: BigInt3
    member R_y: BigInt3
    member s: BigInt3
    member v: felt
end

struct StorageProof:
    member key: IntArray
    member value: IntArray
    member proof: IntArray*
end

struct Proof:
    member address: IntArray
	member state_root: IntArray
    member account_proof: IntArray*
    member balance: felt
    member code_hash: IntArray
    member nonce: felt
    member storage_slot: IntArray
    member storage_hash: IntArray
    member storage_proof: StorageProof
    member signature: Signature
end

func keccak256_20{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(input_ptr: felt*) -> (trie_key: felt*):
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
    let (trie_key) = keccak{keccak_ptr=keccak_ptr}(input, 20)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)
    return (trie_key)
end


## Integer manipulation

func U256_to_ints64(data: IntArray) -> (res: Uint256):
    # TODO
    return (Uint256(0,0))
end

func ints64_to_U256(data: IntArray) -> (res: Uint256):
    # TODO
    return (Uint256(0,0))
end

func ints64_to_bigint3(data: IntArray) -> (res: BigInt3):
    # TODO
    return (BigInt3(0,0,0))
end

func bigint3_to_ints64(data: BigInt3) -> (res: felt*):
    # TODO
    alloc_locals
    local elements : felt*
    return (elements)
end

func felts_to_bigint3(data: felt*) -> (res: BigInt3):
    # TODO
    return (BigInt3(0,0,0))
end


## Array manipulation

func to_int_array(ints_seq: IntsSequence) -> (res: IntArray):
    let res = IntArray(
        elements=ints_seq.element,
        byte_len=ints_seq.element_size_bytes,
        word_len=ints_seq.element_size_words
    )
    return (res)
end

func to_ints_seq(int_array: IntArray) -> (res: IntsSequence):
    let res = IntsSequence(
        elements=int_array.elements,
        element_size_words=int_array.word_len,
        element_size_bytes=int_array.byte_len
    )
    return (res)
end

func to_ints_seq_ptr(int_arrays: IntArray*) -> (res: IntsSequence*):
    # TODO
	let (res : IntsSequence*) = alloc()
    return (res)
end

func slice_arr(array: IntArray, start_pos: felt, end_pos: felt) -> (res: IntArray):
    # TODO
    alloc_locals
    local elements : felt*
    local res: IntArray = IntArray(elements=elements, word_len=0, byte_len=0)
    return (res)
end

func concat_arr(arr_x: IntArray, arr_y: IntArray) -> (res: IntArray):
    # TODO
    alloc_locals
    local elements : felt*
    let res: IntArray = IntArray(elements=elements, word_len=0, byte_len=0)
    return (res)
end


func extract_account{range_check_ptr}(rlp_data: IntsSequence) -> (
        nonce: felt,
        balance: felt,
        storage_root: IntsSequence,
        code_hash: IntsSequence):
    alloc_locals
    let (local storage_root: IntsSequence) = extract_data(5, 32, rlp_data)
    let (local code_hash: IntsSequence) = extract_data(38, 32, rlp_data)
    return (1, 0, storage_root, code_hash)
end

func extract_message_contents(message: IntArray) -> (
    starknet_account: IntArray, storage_root: IntArray, storage_key: IntArray):
    # TODO: Convert hex to bytes
    let (starknet_account) = slice_arr(message, 0, 32)
    let (storage_root) = slice_arr(message, 32, 64)
    let (storage_key) = slice_arr(message, 64, 96)
    return (starknet_account, storage_root, storage_key)
end

func lpad(input: IntArray) -> (res: IntArray):
    # TODO
	let (elements : felt*) = alloc()
    #input.elements[0] # 8 bytes
    #input.elements[1] # 8 bytes
    #input.elements[2] # 4 bytes
    return (IntArray(elements, 4, 32))
end

func encode_kv_position{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        slot: IntArray, address: IntArray) -> (key : IntArray):
    alloc_locals
	let (input : felt*) = alloc()

    # Address
    assert input[0] = 0 
	let (local input1) = swap_endian(address.elements[1], 8)
    assert input[2] = input1
	let (local input2) = swap_endian(address.elements[2], 8)
    assert input[3] = input2
	let (local input3) = swap_endian(address.elements[3], 8)
    assert input[4] = input3

    # Storage slot
	let (local input0) = swap_endian(slot.elements[0], 8)
    assert input[0] = input0 
	let (local input1) = swap_endian(slot.elements[1], 8)
    assert input[1] = input1
	let (local input2) = swap_endian(slot.elements[2], 8)
    assert input[2] = input2    
	let (local input3) = swap_endian(slot.elements[3], 8)
    assert input[3] = input3

    let (out) = keccak256(input, 64)
    local key: IntArray = IntArray(out, 4, 32)
    return (key)
end

func extract_verification_arguments(proof_ptr : Proof*, proof_type: felt) -> (
        root_hash: IntsSequence,
        proof: IntsSequence*,
        proof_len: felt):
    # TODO
    if proof_type == ACCOUNT:
        let (root) = to_ints_seq(proof_ptr.state_root)
        let (proof) = to_ints_seq_ptr(proof_ptr.account_proof)
        #let (len) = proof_ptr.account_proof_len 
        return (root, proof, 0)
    end
    if proof_type == STORAGE:
        let (root) = to_ints_seq(proof_ptr.storage_hash)
        let (proof) = to_ints_seq_ptr(proof_ptr.storage_proof.proof)
        #let (len) = proof_ptr.account_proof_len # TODO
        return (root, proof, 0)
    end
    ret
end

func hash_eip191_message{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        message: IntArray) -> (msg_hash : BigInt3):
    let (output) = keccak256(message.elements, message.byte_len)
    let (msg_hash) = felts_to_bigint3(output)
    return (msg_hash)
end

func recover_address{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        msg_hash: BigInt3, R_x: BigInt3, R_y: BigInt3, s: BigInt3, v: felt) -> (address: IntArray):
    let (public_key) = ecdsa_raw_recover(msg_hash, R_x, R_y, s, v)
    let (elements_x) = bigint3_to_ints64(public_key.y)
    let (elements_y) = bigint3_to_ints64(public_key.y)
    let (elements_pubkey) = concat_arr(IntArray(elements_x, 4, 32), IntArray(elements_y, 4, 32))
    let (hash) = keccak256(elements_pubkey.elements, 64)
    let (address) = slice_arr(IntArray(hash, 4, 32), 12, 32) 
    return (address)
end

func verify_account_proof{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        proof_ptr : Proof*):
    alloc_locals

    # Compute trie key
    let input_ptr : felt* = proof_ptr.address.elements
    let (elements) = keccak256_20(input_ptr)
    local path: IntsSequence = IntsSequence(elements, 4, 32) # 32 bytes (4 64-bit ints)

    # Retrieve RLP encoded account data from proof
    let (root_hash, proof, proof_len) = extract_verification_arguments(proof_ptr, ACCOUNT)
    let (local account_data: IntsSequence) = verify_proof(path, root_hash, proof, proof_len)
    let (nonce, balance, storage_root, code_hash) = extract_account(account_data) 
    
    # TODO: Compare derived hashes
    #assert storage_root = proof_ptr.storage_hash
    #assert code_hash = proof_ptr.code_hash

    return ()
end

func verify_storage_proof{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        proof_ptr : Proof*):
    alloc_locals

    let message = proof_ptr.signature.message
    let R_x = proof_ptr.signature.R_x
    let R_y = proof_ptr.signature.R_y
    let s = proof_ptr.signature.s
    let v = proof_ptr.signature.v

    # Extract Starknet account address, storage root, and storage key from signed message contents
    let (starknet_account, storage_root, storage_key) = extract_message_contents(message)

    # Extract Ethereum account address from signed message hash and signature
    let (msg_hash) = hash_eip191_message(message)
    let (ethereum_address) = recover_address(msg_hash, R_x, R_y, s, v)

    # Verify that signed storage key matches derived trie key
    let storage_slot = proof_ptr.storage_slot
    let (padded_address) = lpad(ethereum_address)
    let (path) = encode_kv_position(storage_slot, ethereum_address)
    assert storage_key = path

    # Retrieve RLP encoded storage value from proof
    let (root_hash, proof, proof_len) = extract_verification_arguments(proof_ptr, STORAGE)
    let (path_) = to_ints_seq(path)
    let (local storage_value: IntsSequence) = verify_proof(path_, root_hash, proof, proof_len)
    let (storage_value_) = to_int_array(storage_value)
    let (balance) = ints64_to_U256(storage_value_)

    # Check that balance is nonzero
    # TODO: More granular verification 
    uint256_lt(Uint256(0,0), balance)

    return ()
end

# Load proof from json file
func encode_proof() -> (proof : Proof*):
    alloc_locals

    local balance : felt
    local nonce : felt

    local elements : felt*
	local elements2 : felt*
    local elements4 : felt*
    local elements5 : felt*
    local elements6 : felt*

    local message : IntArray
    local message_hash : BigInt3
    local R_x : BigInt3
    local R_y : BigInt3
    local v : felt

	let (account_proof : IntArray*) = alloc()
    local storage_proof : StorageProof

    %{
        def load_ints(felts, byte_str):
            for i in range(0, len(byte_str) // 16):
                memory[felts + i] = int(byte_str[i*16 : (i+1) * 16], 16)

        # Contract address
        address = program_input['address'][2:]
        ids.elements = elements = segments.add()
        for i in range(0, len(address) // 16 + 1):
            memory[elements + i] = int(address[i*16 : (i+1) * 16], 16)
            #print(hex(memory[elements + i])[2:])

        # State root
        state_root = program_input['stateRoot'][2:]
        ids.elements2 = elements2 = segments.add()
        for i in range(0, len(state_root) // 16):
            memory[elements2 + i] = int(state_root[i*16 : (i+1) * 16], 16)

        # Account proofs
        for i, proof in enumerate(program_input['accountProof']):
            proof = proof[2:]
            base_addr = ids.account_proof.address_ + ids.IntArray.SIZE * i
            elements3 = segments.add()
            for j in range(0, len(proof) // 16 + 1):
                memory[elements3 + j] = int(proof[j*16 : (j+1) * 16], 16)
            memory[base_addr + ids.IntArray.elements] = elements3
            memory[base_addr + ids.IntArray.byte_length] = int(len(proof) / 2)

        # Balance
        balance = program_input['balance']
        ids.balance = balance

        # Code hash
        code_hash = program_input['codeHash'][2:]
        ids.elements4 = elements4 = segments.add()
        for i in range(0, len(code_hash) // 16):
            memory[elements4 + i] = int(code_hash[i*16 : (i+1) * 16], 16)

        # Nonce
        balance = program_input['balance']
        ids.balance = balance

        # Storage slot
        storage_slot = program_input['storageSlot'][2:]
        ids.elements5 = elements5 = segments.add()
        load_ints(elements5, storage_slot)

        # Storage hash
        storage_hash = program_input['storageHash'][2:]
        ids.elements6 = elements6 = segments.add()
        load_ints(elements6, storage_hash)

        # Storage proof (no support for multiple proofs right now)
        for i, proof in enumerate(program_input['storageProof']):
            key = proof['key'][2:]
            value = proof['value'][2:]
            proof_data = proof['proof'][2:]

        # Signature
        # TODO
	%}

    let address = IntArray(elements=elements, word_len=3, byte_len=20)
    let state_root = IntArray(state_root=elements2, word_len=4, byte_len=32)
    let code_hash = IntArray(state_root=elements4, word_len=4, byte_len=32)
    let storage_slot = IntArray(state_root=elements5, word_len=4, byte_len=32)
    let storage_hash = IntArray(state_root=elements6, word_len=4, byte_len=32)
    let signature = Signature(
        message=message, message_hash=message_hash, R_x=R_x, R_y=R_y, v=v)

    local proof : Proof = Proof(
        address=address,
        state_root=state_root,
        account_proof=account_proof,
        balance=balance,
        code_hash=code_hash,
        nonce=nonce,
        storage_slot=storage_slot,
        storage_hash=storage_hash,
        storage_proof=storage_proof,
        signature=signature)

    let (__fp__, _) = get_fp_and_pc()
    return (proof=&proof)
end

func main{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}():
    alloc_locals
    let (local proof: Proof*) = encode_proof()

    let (__fp__, _) = get_fp_and_pc()
    verify_account_proof(proof_ptr=proof)
    verify_storage_proof(proof_ptr=proof)

    ret
end
