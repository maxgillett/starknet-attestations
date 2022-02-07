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
    member proof: IntsSequence*
end

struct Proof:
    member address: IntArray
	member state_root: IntArray
    member account_proof: IntsSequence*
    member account_proof_len: felt
    member balance: felt
    member code_hash: IntArray
    member nonce: felt
    member storage_slot: IntArray
    member storage_hash: IntArray
    member storage_proof: StorageProof
    member storage_proof_len: felt
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
        element=int_array.elements,
        element_size_words=int_array.word_len,
        element_size_bytes=int_array.byte_len
    )
    return (res)
end

#func to_ints_seq_ptr(int_arrays: IntArray*) -> (res: IntsSequence*):
#    # TODO
#    int_arrays
#	let (res : IntsSequence*) = alloc()
#    return (res)
#end

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

    let (local keccak_ptr : felt*) = alloc()
    let (out) = keccak256{keccak_ptr=keccak_ptr}(input, 64)
    local key: IntArray = IntArray(out, 4, 32)
    return (key)
end

func extract_verification_arguments(proof_ptr : Proof*, proof_type: felt) -> (
        root_hash: IntsSequence,
        proof: IntsSequence*,
        proof_len: felt):
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

func hash_eip191_message{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        message: IntArray) -> (msg_hash : BigInt3):
    alloc_locals
    let (local keccak_ptr : felt*) = alloc()
    let (output) = keccak256{keccak_ptr=keccak_ptr}(message.elements, message.byte_len)
    let (msg_hash) = felts_to_bigint3(output)
    return (msg_hash)
end

func recover_address{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        msg_hash: BigInt3, R_x: BigInt3, R_y: BigInt3, s: BigInt3, v: felt) -> (address: IntArray):
    alloc_locals
    let (public_key) = ecdsa_raw_recover(msg_hash, R_x, R_y, s, v)
    let (elements_x) = bigint3_to_ints64(public_key.y)
    let (elements_y) = bigint3_to_ints64(public_key.y)
    let (elements_pubkey) = concat_arr(IntArray(elements_x, 4, 32), IntArray(elements_y, 4, 32))
    let (local keccak_ptr : felt*) = alloc()
    let (hash) = keccak256{keccak_ptr=keccak_ptr}(elements_pubkey.elements, 64)
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
    %{
        output = ''.join(v.to_bytes(8, 'little').hex() for v in memory.get_range(ids.path.element, 4))
        print(output)
        from web3 import Web3
        assert '0x' + output == Web3.keccak(0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72).hex()
        output2 = ''.join(v.to_bytes(8, 'big').hex() for v in memory.get_range(ids.root_hash.element, 4))
        print(output2)
    %}
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
    local account_proof_len : felt
    local storage_proof_len : felt

    local address : IntArray
    local state_root : IntArray 
    local code_hash : IntArray 
    local storage_slot : IntArray
    local storage_hash : IntArray

    local message : IntArray
    local message_hash : BigInt3
    local R_x : BigInt3
    local R_y : BigInt3
    local v : felt

	let (account_proof : IntsSequence*) = alloc()
	let (storage_proof0 : IntsSequence*) = alloc()

    local storage_key : IntArray
    local storage_value : IntArray

    %{
        from starkware.cairo.common.cairo_secp.secp_utils import split
        
        def load_ints(felts, byte_str):
            for i in range(0, len(byte_str) // 16):
                memory[felts + i] = int(byte_str[i*16 : (i+1) * 16], 16)

        def load_intarray(base_addr, hex_input):
            elements = segments.add()
            for j in range(0, len(hex_input) // 16 + 1):
                hex_str = hex_input[j*16 : (j+1) * 16]
                if len(hex_str) > 0:
                    memory[elements + j] = int(hex_str, 16)
            memory[base_addr + ids.IntArray.elements] = elements
            memory[base_addr + ids.IntArray.word_len] = int(len(hex_input) / 2 / 8)
            memory[base_addr + ids.IntArray.byte_len] = int(len(hex_input) / 2)

        # TODO: Combine usage of IntArray and IntsSequence into single data struct
        def load_intseq(base_addr, hex_input):
            elements = segments.add()
            for j in range(0, len(hex_input) // 16 + 1):
                hex_str = hex_input[j*16 : (j+1) * 16]
                if len(hex_str) > 0:
                    memory[elements + j] = int(hex_str, 16)
            memory[base_addr + ids.IntsSequence.element] = elements
            memory[base_addr + ids.IntsSequence.element_size_words] = int(len(hex_input) / 2 / 8)
            memory[base_addr + ids.IntsSequence.element_size_bytes] = int(len(hex_input) / 2)

        def load_bigint3(base_addr, input):
            d0, d1, d2 = split(input)
            memory[base_addr + ids.BigInt3.d0] = d0
            memory[base_addr + ids.BigInt3.d1] = d1
            memory[base_addr + ids.BigInt3.d2] = d2

        ids.balance = program_input['balance']
        ids.nonce = program_input['nonce']
        ids.account_proof_len = len(program_input['accountProof'])
        ids.storage_proof_len = len(program_input['storageProof'][0]['proof'])

        load_intarray(ids.address.address_, program_input['address'][2:])
        load_intarray(ids.state_root.address_, program_input['stateRoot'][2:])
        load_intarray(ids.code_hash.address_, program_input['codeHash'][2:])
        load_intarray(ids.storage_slot.address_, program_input['storageSlot'][2:])
        load_intarray(ids.storage_hash.address_, program_input['storageHash'][2:])
        load_intarray(ids.storage_key.address_, program_input['storageProof'][0]['key'][2:])
        load_intarray(ids.storage_value.address_, program_input['storageProof'][0]['value'][2:])

        # Account proof
        for i, proof in enumerate(program_input['accountProof']):
            base_addr = ids.account_proof.address_ + ids.IntsSequence.SIZE * i
            load_intseq(base_addr, proof[2:])

        # Storage proof (TODO: add support for more than one proof)
        for i, proof in enumerate(program_input['storageProof'][0]['proof']):
            base_addr = ids.storage_proof0.address_ + ids.IntsSequence.SIZE * i
            load_intseq(base_addr, proof[2:])

        # Signature
        load_intarray(ids.message.address_, program_input['signature']['message'][2:])
        load_bigint3(ids.message_hash.address_, int(program_input['signature']['messageHash'], 16))
        load_bigint3(ids.R_x.address_, program_input['signature']['R_x'])
        load_bigint3(ids.R_y.address_, program_input['signature']['R_y'])
        ids.v = program_input['signature']['v']
	%}

    local storage_proof : StorageProof = StorageProof(
        key=storage_key, value=storage_value, proof=storage_proof0)
    local signature : Signature = Signature(
        message=message, message_hash=message_hash, R_x=R_x, R_y=R_y, v=v)
    local proof: Proof = Proof(
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

func main{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}():
    alloc_locals
    let (local proof: Proof*) = encode_proof()

    let (__fp__, _) = get_fp_and_pc()
    verify_account_proof(proof_ptr=proof)
    verify_storage_proof(proof_ptr=proof)

    ret
end
