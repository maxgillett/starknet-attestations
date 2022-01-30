%builtins output range_check bitwise

from lib.keccak import keccak, finalize_keccak
from lib.storage_verification import keccak256
from lib.storage_verification.trie_proofs import verify_proof
from lib.bytes_utils import slice, IntArray, swap_endian
from lib.trie.hexary import get_from_proof
from lib.secp import ecdsa_raw_recover

from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

const ACCOUNT = 1
const STORAGE = 2

struct Signature:
    member R_x: BigInt3,
    member R_y: BigInt3,
    member s: BigInt3,
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
    member code_hash: IntArry
    member nonce: felt
    member storage_hash: IntArray
    member storage_proof: StorageProof
end

func keccak256_20(input_ptr: felt*) -> (trie_key: felt):
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


func U256_to_ints64(data: IntArray) -> (res: U256):
    # TODO
end

func ints64_to_U256(data: IntArray) -> (res: U256):
    # TODO
end

func ints64_to_bigint3(data: IntArray) -> (res: BigInt3):
    # TODO
end

func bigint3_to_ints64(data: BigInt3) -> (res: felt*):
    # TODO
end

func extract_account(rlp_data) -> (nonce: felt, balance: felt, storage_root: IntSequence, code_hash: IntSequence):
    let (storage_root) = extract_data(rlp_data, 5, 32)
    let (code_hash) = extract_data(rlp_data, 38, 32)
    return (1, 0, storage_root, code_hash)
end

func extract_message_contents(message) -> ():
    # TODO
end

func encode_kv_position(slot, address) -> (key : IntArray*):
	let (input : felt*) = alloc()
    keccak256(input, 64)
    return (key)
end

func extract_verification_arguments(proof_ptr : Proof*, proof_type: felt) -> ():
    if proof_type == ACCOUNT:
        # TODO
    end
    if proof_type == STORAGE:
        # TODO
    end
end

func hash_eip191_message(message: IntArray*) -> (msg_hash : BigInt3):
	let (message : felt*) = alloc()
    let (output) = keccak256(message)
    let (msg_hash) = felts_to_bigint3(output)
    return (msg_hash)
end

func recover_address(
    msg_hash: BigInt3, R_x: BigInt3, R_y: BigInt3, s: BigInt3, v: felt) -> (address: IntArray*):
    let (public_key) = ecdsa_raw_recover(msg_hash, R_x, R_y, s, v)
    return (address)
end

func verify_account_proof{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        proof_ptr : Proof*):
    alloc_locals

    # Compute trie key
    let input_ptr : felt* = proof_ptr.address.elements
    let (elements) = keccak256_20(input_ptr)
    let (path) = IntsSequence(elements, )

    # Retrieve RLP encoded account data from proof
    let (root_hash, proof, proof_len) = extract_verification_arguments(proof_ptr, ACCOUNT)
    let (local account_data: IntsSequence) = verify_proof(path, root_hash, proof, proof_len)
    let (nonce, balance, storage_root, code_hash) = extract_account(account_data) 
    
    assert storage_root == proof_ptr.storage_root
    assert code_hash == proof_ptr.code_hash

    return ()
end

func verify_storage_proof{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
        proof_ptr : Proof*):
    alloc_locals

    # Extract Starknet account address, storage root, and storage key from signed message contents
    let (starknet_account, storage_root, storage_key) = extract_message_contents(message)

    # Extract Ethereum account address from signed message hash and signature
    let (msg_hash) = hash_eip191_message(message)
    let (ethereum_account) = recover_address(msg_hash, R_x, R_y, s, v)

    # Verify that signed storage key matches derived trie key
    let (path) = encode_kv_position(storage_slot, ethereum_account)
    assert storage_key = path

    # Retrieve RLP encoded storage value from proof
    let (root_hash, proof, proof_len) = extract_verification_arguments(proof_ptr, STORAGE)
    let (local storage_value: IntsSequence) = verify_proof(path, root_hash, proof, proof_len)
    let (balance) = ints64_to_U256(storage_value)

    # Check that balance is nonzero
    uint256_lt(Uint256(0), balance)
end

func encode_proof() -> (proof : Proof*):
    alloc_locals

    local elements : felt*
	local elements2 : felt*
	let (account_proof : IntArray*) = alloc()
    %{
        def convert_to_ints():
            pass

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
	%}
    let address = IntArray(elements=elements, byte_length=20)
    let state_root = IntArray(state_root=elements2, byte_length=32)
    local proof : Proof = Proof(address=address, state_root=state_root, account_proof=account_proof)

    let (__fp__, _) = get_fp_and_pc()
    return (proof=&proof)
end

func main{output_ptr : felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}():
    let (proof) = encode_proof()

    let (__fp__, _) = get_fp_and_pc()
    verify_account_proof(proof_ptr=proof)
    verify_storage_proof(proof_ptr=proof)

    ret
end
