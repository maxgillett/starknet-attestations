import os, json
import sympy
from dotenv import load_dotenv
from web3 import Web3
from eth_account.messages import encode_defunct

ERC20_TOKEN = "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72" # ENS token
BLOCK_NUMBER = 14063681

load_dotenv()
ADDRESS = os.environ['ADDRESS']
PRIVATE_KEY = os.environ['PRIVATE_KEY']
STARKNET_ATTESTATION_WALLET = os.environ['STARKNET_ATTESTATION_WALLET']
w3 = Web3(Web3.HTTPProvider(os.environ['RPC_HTTP']))

# Create storage proof for an ERC20 balance at a particular block number
slot = str(0).rjust(64, '0')
key = ADDRESS[2:].rjust(64, '0').lower()
position = w3.keccak(hexstr=key + slot)
print(Web3.toHex(position))
block = w3.eth.get_block(BLOCK_NUMBER)
proof = w3.eth.get_proof(ERC20_TOKEN, [position], BLOCK_NUMBER)
balance = w3.eth.get_storage_at(ERC20_TOKEN, position)
print("Generating proof of balance", Web3.toInt(balance))

# Sign a message demonstrating control over the storage slot
state_root = block.stateRoot.hex()
storage_key = proof['storageProof'][0]['key'].hex()[2:]
msg = "000000%s%s%s00000000" % ( # Pad the message with zeros to align 64bit word size in Cairo
    STARKNET_ATTESTATION_WALLET[2:],
    state_root[2:],
    storage_key)
message = encode_defunct(hexstr=msg)
signed_message = w3.eth.account.sign_message(message, private_key=PRIVATE_KEY)
eip191_message = b'\x19' + message.version + message.header + message.body
P = 2**256 - 4294968273
R_x = signed_message.r
R_y = min(sympy.ntheory.residue_ntheory.sqrt_mod(R_x**3 + 7, P, all_roots=True))

# Debug: split message into 64bit uints
def pack_intarray(hex_input):
    elements = []
    for j in range(0, len(hex_input) // 16 + 1):
        hex_str = hex_input[j*16:(j+1)*16]
        if len(hex_str) > 0:
            elements.append(int(hex_str, 16))
    return elements
print(pack_intarray(message.body.hex()[6:]))
print(pack_intarray(eip191_message.hex()[:])[4:]) # Skip the first 4 words
print(message.body.hex()[6:])
print(eip191_message.hex())

# Serialize proof to disk
proof_dict = json.loads(Web3.toJSON(proof))
proof_dict['blockNumber'] = block.number
proof_dict['stateRoot'] = state_root
proof_dict['storageSlot'] = slot
proof_dict["signature"] = {
    "message": "0x"+eip191_message.hex(),
    "messageHash": signed_message.messageHash.hex(),
    "R_x": signed_message.r,
    "R_y": R_y,
    "s": signed_message.s,
    "v": signed_message.v,
}
json.dump(proof_dict, open("proof.json", "w"), indent=4)
