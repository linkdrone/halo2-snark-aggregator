#!/bin/sh

mkdir -p hardhat/
mkdir -p hardhat/contracts
mkdir -p hardhat/test/output
cp ../halo2-snark-aggregator-sdk/output/verifier.sol hardhat/contracts/Verifier.sol
cp ../halo2-snark-aggregator-sdk/output/verify_circuit_proof.data hardhat/test/output/verify_circuit_proof.data
cp ../halo2-snark-aggregator-sdk/output/verify_circuit_final_pair.data hardhat/test/output/verify_circuit_final_pair.data
cd hardhat
yarn install
cd -
