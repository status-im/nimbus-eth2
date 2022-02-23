# Clone repos

`git clone --branch thegostep/docs https://github.com/flashbots/mev-boost.git`

Apply
```diff
diff --git a/lib/service.go b/lib/service.go
index cd3e88e..b477fb5 100644
--- a/lib/service.go
+++ b/lib/service.go
@@ -8,6 +8,7 @@ import (
 	"io"
 	"io/ioutil"
 	"log"
+ 	"math/big"
 	"net/http"
 
 	"github.com/ethereum/go-ethereum/common"
@@ -165,6 +166,11 @@ func (m *RelayService) ProposeBlindedBlockV1(r *http.Request, args *SignedBlinde
 		blockHash = body.ExecutionPayloadCamel.BlockHashCamel
 	}
 
+    var foo ExecutionPayloadWithTxRootV1
+    foo = ExecutionPayloadWithTxRootV1{BaseFeePerGas: big.NewInt(4)}
+    *result = foo
+    return nil
+
 	payloadCached := m.store.Get(common.HexToHash(blockHash))
 	if payloadCached != nil {
 		log.Println(green("ProposeBlindedBlockV1: ✓ revealing previous payload from execution client: "), payloadCached.BlockHash, payloadCached.Number, payloadCached.TransactionsRoot)
@@ -197,6 +203,11 @@ var nilHash = common.Hash{}
 
 // GetPayloadHeaderV1 TODO
 func (m *RelayService) GetPayloadHeaderV1(r *http.Request, args *string, result *ExecutionPayloadWithTxRootV1) error {
+    var foo ExecutionPayloadWithTxRootV1
+    foo = ExecutionPayloadWithTxRootV1{BaseFeePerGas: big.NewInt(4)}
+    *result = foo
+    return nil;
+
 	executionResp, executionErr := makeRequest(m.executionURL, "engine_getPayloadV1", []interface{}{*args})
 	relayResp, relayErr := makeRequest(m.relayURL, "engine_getPayloadV1", []interface{}{*args})
```
if one wants to just test the RPC without a relay or execution client, only the builder.

# Build and run the mev-boost command

In the `mev-boost/cmd/mev-boost` directory, run `go build . && ./mev_boost`:
```
$ go build . && ./mev-boost 
mev-boost: 2022/02/23 06:45:07 main.go:29: listening on:  18550
```

# Run the Nimbus-side RPC test

This currently accesses a field in eth1_monitor directly:
```nim
diff --git a/beacon_chain/eth1/eth1_monitor.nim b/beacon_chain/eth1/eth1_monitor.nim
index b2cebda8..06d55f15 100644
--- a/beacon_chain/eth1/eth1_monitor.nim
+++ b/beacon_chain/eth1/eth1_monitor.nim
@@ -127,3 +127,3 @@ type
     url: string
-    web3: Web3
+    web3*: Web3
     ns: Sender[DepositContract]
```
Pending further integration into eth1_monitor.

If that's in place, run:
```
$ ./env.sh nim c --hints:off -r scripts/test_mev_boost

[Suite] mev-boost RPC
DBG 2022-02-23 06:47:19.710+01:00 Message sent to RPC server                 topics="JSONRPC-HTTP-CLIENT" tid=635228 file=httpclient.nim:68 address="ok((id: \"127.0.0.1:18550\", scheme: NonSecure, hostname: \"127.0.0.1\", port: 18550, path: \"\", query: \"\", anchor: \"\", username: \"\", password: \"\", addresses: @[127.0.0.1:18550]))" msg_len=553
  [OK] builder_ProposeBlindedBlockV1
DBG 2022-02-23 06:47:19.713+01:00 Message sent to RPC server                 topics="JSONRPC-HTTP-CLIENT" tid=635228 file=httpclient.nim:68 address="ok((id: \"127.0.0.1:18550\", scheme: NonSecure, hostname: \"127.0.0.1\", port: 18550, path: \"\", query: \"\", anchor: \"\", username: \"\", password: \"\", addresses: @[127.0.0.1:18550]))" msg_len=94
  [OK] builder_getPayloadHeaderV1
$
```

The RPC traffic looks like:
```
POST / HTTP/1.1\r
Accept: */*\r
Content-Length: 553\r
Content-Type: application/json\r
Host: 127.0.0.1\r
Connection: keep-alive\r
User-Agent: nim-chronos/3.0.2 (amd64/linux)\r
\r
{"jsonrpc":"2.0","method":"builder_proposeBlindedBlockV1","params":[{"message":{"slot":"0x0","proposer_index":"0x0","parent_root":"0x0000000000000000000000000000000000000000000000000000000000000000","state_root":"0x0000000000000000000000000000000000000000000000000000000000000000","body":{"execution_payload_header":{"blockHash":""}}},"signature":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}],"id":1}< 2022/02/23 06:28:43.588446  length=887 from=0 to=886
HTTP/1.1 200 OK\r
Content-Type: application/json; charset=utf-8\r
X-Content-Type-Options: nosniff\r
Date: Wed, 23 Feb 2022 05:28:43 GMT\r
Content-Length: 730\r
\r
{"jsonrpc":"2.0","result":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x0","gasLimit":"0x0","gasUsed":"0x0","timestamp":"0x0","extraData":"0x","baseFeePerGas":"0x4","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000"},"error":null,"id":1}
> 2022/02/23 06:28:43.590617  length=264 from=0 to=263
POST / HTTP/1.1\r
Accept: */*\r
Content-Length: 94\r
Content-Type: application/json\r
Host: 127.0.0.1\r
Connection: keep-alive\r
User-Agent: nim-chronos/3.0.2 (amd64/linux)\r
\r
{"jsonrpc":"2.0","method":"builder_getPayloadHeaderV1","params":["0x0000000000000000"],"id":1}< 2022/02/23 06:28:43.591736  length=887 from=0 to=886
HTTP/1.1 200 OK\r
Content-Type: application/json; charset=utf-8\r
X-Content-Type-Options: nosniff\r
Date: Wed, 23 Feb 2022 05:28:43 GMT\r
Content-Length: 730\r
\r
{"jsonrpc":"2.0","result":{"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","feeRecipient":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x","random":"0x0000000000000000000000000000000000000000000000000000000000000000","blockNumber":"0x0","gasLimit":"0x0","gasUsed":"0x0","timestamp":"0x0","extraData":"0x","baseFeePerGas":"0x4","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000"},"error":null,"id":1}
```

This exercises the RPC serialization and deserialization.
