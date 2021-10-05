#!/usr/bin/env bash
set -Eeuo pipefail

# https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
#
# git clone --branch merge-interop-spec https://github.com/MariusVanDerWijden/go-ethereum.git
#
# Last checked against geth as of
# commit d6b04900423634d27be1178edf46622394085bb9 (HEAD -> merge-interop-spec, origin/merge-interop-spec)
# Author: Marius van der Wijden <m.vanderwijden@live.de>
# Date:   Wed Sep 29 19:24:56 2021 +0200
#
#     eth/catalyst: fix random in payload, payloadid as hexutil

# Prepare a payload
resp_prepare_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_preparePayload","params":[{"parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131", "timestamp":"0x5", "random":"0x0000000000000000000000000000000000000000000000000000000000000000", "feeRecipient":"0x0000000000000000000000000000000000000000"}],"id":67}' http://localhost:8545)
echo "engine_preparePayload response: ${resp_prepare_payload}"
# Interop version of response, not current main version of response
[[ ${resp_prepare_payload} == '{"jsonrpc":"2.0","id":67,"result":"0x0"}' ]] || (echo "Unexpected response to engine_preparePayload"; false)

# Get the payload
resp_get_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_getPayload","params":["0x0"],"id":67}' http://localhost:8545)
echo "engine_getPayload response: ${resp_get_payload}"

expected_resp_get_payload='{"jsonrpc":"2.0","id":67,"result":{"blockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174","parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131","coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x989680","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x0","transactions":[]}}'
empirical_resp_get_payload='{"jsonrpc":"2.0","id":67,"result":{"blockHash":"0x7a694c5e6e372e6f865b073c101c2fba01f899f16480eb13f7e333a3b7e015bc","parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131","coinbase":"0x0000000000000000000000000000000000000000","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x989680","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x0","transactions":[]}}'
[[ ${resp_get_payload} == ${expected_resp_get_payload} ]] || [[ ${resp_get_payload} == ${empirical_resp_get_payload} ]] || (echo "Unexpected response to engine_getPayload"; false)

# Execute the payload
# Needed two tweaks vs upstream note: (a) add blockNumber field and (b) switch receiptRoots to receiptRoot
resp_execute_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_executePayload","params":[{"blockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174","parentHash":"0xa0513a503d5bd6e89a144c3268e5b7e9da9dbf63df125a360e3950a7d0d67131","coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","number":"0x1","gasLimit":"0x989680","gasUsed":"0x0","blockNumber":"0x1","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x0","transactions":[]}],"id":67}' http://localhost:8545)
[[ ${resp_execute_payload} == '{"jsonrpc":"2.0","id":67,"result":{"status":"VALID"}}' ]] || (echo "Unexpected response to engine_executePayload"; false)

# Mark the payload as valid
resp_consensus_validated=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_consensusValidated","params":[{"blockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174", "status":"VALID"}],"id":67}' http://localhost:8545)
[[ ${resp_consensus_validated} == '{"jsonrpc":"2.0","id":67,"result":null}' ]] || (echo "Unexpected response to engine_consensusValidated"; false)

# Update the fork choice
resp_fork_choice_updated=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_forkChoiceUpdated","params":[{"headBlockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174", "finalizedBlockHash":"0xb084c10440f05f5a23a55d1d7ebcb1b3892935fb56f23cdc9a7f42c348eed174"}],"id":67}' http://localhost:8545)
[[ ${resp_consensus_validated} == '{"jsonrpc":"2.0","id":67,"result":null}' ]] || (echo "Unexpected response to engine_forkChoiceUpdated"; false)

echo "Execution test vectors for Merge passed"
