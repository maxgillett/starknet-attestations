from typing import NamedTuple, List

from web3 import Web3

class BigInt3(NamedTuple):
    d0: int
    d1: int
    d2: int

class IntArray(NamedTuple):
    elements: List[int]

a = BigInt3(0xe28d959f2815b16f81798, 0xa573a1c2c1c0a6ff36cb7, 0x79be667ef9dcbbac55a06)
b = Web3.toInt(hexstr="0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

BASE_20 = 2**20
BASE_42 = 2**42
BASE_64 = 2**64

def bigint3_to_ints64(a: BigInt3):
    c1 = a.d0 & (BASE_64 - 1)  # 64 bit

    c2 = a.d0 >> 64            # 22 bit
    c3 = a.d1 & (BASE_42 - 1)  # 42 bit
    
    c4 = a.d1 >> 42            # 44 bit
    c5 = a.d2 & (BASE_20 - 1)  # 20 bit

    c6 = (a.d2 >> 20) & (BASE_64 - 1)  # 64 bit

    c7 = a.d2 >> 84  # 2 bit

    return IntArray(elements=[
        c1, c2+c3, c4+c5, c6, c7
    ])

def ints64_to_bigint3(a: IntArray):
    return sum([item*BASE_64**n for (n, item) in enumerate(a.elements)])

res = bigint3_to_ints64(a)
res2 = ints64_to_bigint3(res)

print(res)
print(res2)
