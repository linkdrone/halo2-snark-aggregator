#!/bin/sh

mkdir -p hardhat/
mkdir -p hardhat/contracts
cp ../halo2-snark-aggregator-sdk/output/verifier.sol hardhat/contracts/Verifier.sol
cd hardhat
yarn install
cd -
