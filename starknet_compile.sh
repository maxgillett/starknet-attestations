#!/bin/bash

starknet-compile contract.cairo \
    --output contract_compiled.json \
    --abi contract_abi.json
