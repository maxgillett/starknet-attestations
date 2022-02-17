#!/bin/bash

cairo-compile contract.cairo --output contract.json
cairo-compile verify_proof.cairo --output verify_proof_compiled.json
PYTHONPATH=. cairo-run --program=verify_proof_compiled.json \
    --print_output --layout=all \
    --program_input=proof.json

