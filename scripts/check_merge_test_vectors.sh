#!/usr/bin/env bash
set -Eeuo pipefail

# https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
#
# git clone --branch kintsugi-spec https://github.com/MariusVanDerWijden/go-ethereum.git
#
# Last checked against geth as of
# commit 98240256ee51811c6b2806783c160aaf6f965f6b (HEAD -> kintsugi-spec, origin/kintsugi-spec)
# Author: Marius van der Wijden <m.vanderwijden@live.de>
# Date:   Sat Nov 6 14:28:21 2021 +0100
#
#     eth/catalyst: remove headHash from payloadAttributes

# Prepare payload
resp_prepare_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV1","params":[{"headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a", "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a", "finalizedBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}, {"timestamp":"0x5", "random":"0x0000000000000000000000000000000000000000000000000000000000000000", "feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"}],"id":67}' http://localhost:8550)
echo "engine_forkchoiceUpdatedV1 response: ${resp_prepare_payload}"

# Inconsistency in test vectors vs Geth behavior
expected_resp_prepare_payload='{"jsonrpc":"2.0","id":67,"result":{"status":"VALID","payloadId":"0xa247243752eb10b4"}}'
empirical_resp_prepare_payload='{"jsonrpc":"2.0","id":67,"result":{"status":"SUCCESS","payloadId":"0xa247243752eb10b4"}}'
[[ ${resp_prepare_payload} == "${expected_resp_prepare_payload}" ]] || [[ ${resp_prepare_payload} == "${empirical_resp_prepare_payload}" ]] || (echo "Unexpected response to engine_forkchoiceUpdatedV1"; false)

# Get payload
resp_get_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_getPayloadV1","params":["0xa247243752eb10b4"],"id":67}' http://localhost:8550)
echo "engine_getPayloadV1 response: ${resp_get_payload}"

expected_resp_get_payload='{"jsonrpc":"2.0","id":67,"result":{"parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a","coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x7","blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858","transactions":[]}}'
[[ ${resp_get_payload} == "${expected_resp_get_payload}" ]] || (echo "Unexpected response to engine_getPayloadV1"; false)

# Execute payload
resp_execute_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_executePayloadV1","params":[{"parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a","coinbase":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x7","blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858","transactions":[]}],"id":67}' http://localhost:8550)
echo "engine_executePayloadV1 response: ${resp_execute_payload}"

# SUCCESS vs VALID again, but in the other direction
expected_resp_execute_payload='{"jsonrpc":"2.0","id":67,"result":{"status":"SUCCESS","latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858"}}'
empirical_resp_execute_payload='{"jsonrpc":"2.0","id":67,"result":{"status":"VALID","latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858"}}'
[[ ${resp_execute_payload} == "${expected_resp_execute_payload}" ]] || [[ ${resp_execute_payload} == "${empirical_resp_execute_payload}" ]] || (echo "Unexpected response to engine_executePayloadV1"; false)

# Update the fork choice
resp_update_forkchoice=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV1","params":[{"headBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858", "safeBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858", "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"}, null],"id":67}' http://localhost:8550)
echo "engine_forkchoiceUpdatedV1 response: ${resp_update_forkchoice}"

expected_resp_update_forkchoice='{"jsonrpc":"2.0","id":67,"result":{"status":"SUCCESS","payloadId":null}}'
[[ ${resp_update_forkchoice} == "${expected_resp_update_forkchoice}" ]] || (echo "Unexpected response to engine_forkchoiceUpdatedV1"; false)

echo "kintsugi test vectors passed"
