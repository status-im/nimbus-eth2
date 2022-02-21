#!/usr/bin/env bash
set -Eeu

# https://notes.ethereum.org/rmVErCfCRPKGqGkUe89-Kg
#
# git clone --branch merge-kiln https://github.com/MariusVanDerWijden/go-ethereum.git

# Prepare payload
resp_prepare_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV1","params":[{"headBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a", "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a", "finalizedBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}, {"timestamp":"0x5", "random":"0x0000000000000000000000000000000000000000000000000000000000000000", "suggestedFeeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"}],"id":67}' http://localhost:8550)
echo "engine_forkchoiceUpdatedV1 response: ${resp_prepare_payload}"

# Inconsistency in test vectors vs Geth behavior
empirical_resp_prepare_payload='{"jsonrpc":"2.0","id":67,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":"0xa247243752eb10b4"}}'
expected_resp_prepare_payload='{"jsonrpc":"2.0","id":67,"result":{"payloadStatus":{"status":"VALID","latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000000","validationError":""},"payloadId":"0xa247243752eb10b4"}}'
[[ ${resp_prepare_payload} == "${empirical_resp_prepare_payload}" ]] || [[ ${resp_prepare_payload} == "${expected_resp_prepare_payload}" ]] || (echo "Unexpected response to engine_forkchoiceUpdatedV1"; false)

# Get the payload
resp_get_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_getPayloadV1","params":["0xa247243752eb10b4"],"id":67}' http://localhost:8550)
echo "engine_getPayloadV1 response: ${resp_get_payload}"

expected_resp_get_payload='{"jsonrpc":"2.0","id":67,"result":{"parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a","feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x1c95111","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x7","blockHash":"0x6359b8381a370e2f54072a5784ddd78b6ed024991558c511d4452eb4f6ac898c","transactions":[]}}'
[[ ${resp_get_payload} == "${expected_resp_get_payload}" ]] || (echo "Unexpected response to engine_getPayloadV1"; false)

# Execute the payload
resp_new_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_newPayloadV1","params":[{"parentHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a","feeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","stateRoot":"0xca3149fa9e37db08d1cd49c9061db1002ef1cd58db2210f2115c8c989b2bdf45","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x5","extraData":"0x","baseFeePerGas":"0x7","blockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858","transactions":[]}],"id":67}' http://localhost:8550)
echo "engine_executePayloadV1 response: ${resp_new_payload}"

expected_resp_new_payload='{"jsonrpc":"2.0","id":67,"result":{"status":"VALID","latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858","validationError":""}}'
empirical_resp_new_payload='{"jsonrpc":"2.0","id":67,"result":{"status":"VALID","latestValidHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858","validationError":null}}'
[[ ${resp_new_payload} == "${empirical_resp_new_payload}" ]] || [[ ${resp_new_payload} == "${expected_resp_new_payload}" ]] || (echo "Unexpected response to engine_newPayloadV1"; false)

# Update the fork choice
resp_update_forkchoice=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV1","params":[{"headBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858", "safeBlockHash":"0x3559e851470f6e7bbed1db474980683e8c315bfce99b2a6ef47c057c04de7858", "finalizedBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a"}, null],"id":67}' http://localhost:8550)
echo "engine_forkchoiceUpdatedV1 response: ${resp_update_forkchoice}"

expected_resp_update_forkchoice='{"jsonrpc":"2.0","id":67,"result":{"payloadStatus":{"status":"VALID","latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000000","validationError":""},"payloadId":null}}'
empirical_resp_update_forkchoice='{"jsonrpc":"2.0","id":67,"result":{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},"payloadId":null}}'
[[ ${resp_update_forkchoice} == "${empirical_resp_update_forkchoice}" ]] || [[ ${resp_update_forkchoice} == "${expected_resp_update_forkchoice}" ]] || (echo "Unexpected response to engine_forkchoiceUpdatedV1"; false)

## Error cases

# invalid payload length
resp_invalid_payload_length=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_getPayloadV1","params":["0x01"],"id":67}' http://localhost:8550)
echo "engine_getPayloadV1 error case response: ${resp_invalid_payload_length}"

expected_resp_invalid_payload_length='{"jsonrpc":"2.0","id":67,"error":{"code":-32602,"message":"invalid argument 0: invalid payload id \"0x01\": hex string has length 2, want 16 for PayloadID"}}'
[[ ${resp_invalid_payload_length} == "${expected_resp_invalid_payload_length}" ]] || (echo "Unexpected response regarding invalid payload length"; false)

# unknown payload
resp_unknown_payload=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_getPayloadV1","params":["0x0000000000000000"],"id":67}' http://localhost:8550)
echo "engine_getPayloadV1 error case response: ${resp_unknown_payload}"

expected_resp_unknown_payload='{"jsonrpc":"2.0","id":67,"error":{"code":-32001,"message":"Unknown payload"}}'
[[ ${resp_unknown_payload} == "${expected_resp_unknown_payload}" ]] || (echo "Unexpected response regarding invalid payload length"; false)

# invalid head
resp_invalid_head=$(curl -sX POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"engine_forkchoiceUpdatedV1","params":[{"headBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000001", "safeBlockHash":"0x3b8fb240d288781d4aac94d3fd16809ee413bc99294a085798a589dae51ddd4a", "finalizedBlockHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}, {"timestamp":"0x5", "random":"0x0000000000000000000000000000000000000000000000000000000000000000", "suggestedFeeRecipient":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"}],"id":67}' http://localhost:8550)
echo "engine_getPayloadV1 case response: ${resp_invalid_head}"

expected_resp_invalid_head='{"jsonrpc":"2.0","id":67,"result":{"payloadStatus":{"status":"SYNCING","latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000000","validationError":""},"payloadId":null}}'
empirical_resp_invalid_head='{"jsonrpc":"2.0","id":67,"result":{"payloadStatus":{"status":"SYNCING","latestValidHash":null,"validationError":null},"payloadId":null}}'
[[ ${resp_invalid_head} == "${empirical_resp_invalid_head}" ]] || [[ ${resp_invalid_head} == "${expected_resp_invalid_head}" ]] || (echo "Unexpected response regarding invalid payload length"; false)

echo "Kiln test vectors passed"
