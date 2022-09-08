#!/usr/bin/env bash
# set -Eeuo pipefail

# https://notes.ethereum.org/rmVErCfCRPKGqGkUe89-Kg

# Genesis block hash: 0xfoobar
# To start miner, run miner.start()
# To increase verbosity: debug.verbosity(4)

GENESISJSON=$(mktemp)
GETHDATADIR=$(mktemp -d)

echo \{\
	\"config\": \{\
		\"chainId\":1,\
		\"homesteadBlock\":0,\
		\"eip150Block\":0,\
		\"eip155Block\":0,\
		\"eip158Block\":0,\
		\"byzantiumBlock\":0,\
		\"constantinopleBlock\":0,\
		\"petersburgBlock\":0,\
		\"istanbulBlock\":0,\
		\"muirGlacierBlock\":0,\
		\"berlinBlock\":0,\
		\"londonBlock\":0,\
		\"clique\": \{\
			\"period\": 5,\
			\"epoch\": 30000\
		\},\
		\"terminalTotalDifficulty\":0\
	\},\
	\"nonce\":\"0x42\",\
	\"timestamp\":\"0x0\",\
	\"extraData\":\"0x0000000000000000000000000000000000000000000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\
	\"gasLimit\":\"0x1C9C380\",\
	\"difficulty\":\"0x400000000\",\
	\"mixHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\
	\"coinbase\":\"0x0000000000000000000000000000000000000000\",\
	\"alloc\":\{\
		\"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b\":\{\"balance\":\"0x6d6172697573766477000000\"\} \
	\},\
	\"number\":\"0x0\",\
	\"gasUsed\":\"0x0\",\
	\"parentHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\
	\"baseFeePerGas\":\"0x7\"\
\} > "${GENESISJSON}"

# Initialize the genesis
~/go-ethereum/build/bin/geth --http --ws -http.api "engine" --datadir "${GETHDATADIR}" init "${GENESISJSON}"

# Import the signing key (press enter twice for empty password)
~/go-ethereum/build/bin/geth --http --ws -http.api "engine" --datadir "${GETHDATADIR}" account import <(echo 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8)

# Start the node (and press enter once to unlock the account)
~/go-ethereum/build/bin/geth --http --ws --http.api "eth,net,engine" -ws.api "eth,net,engine" --datadir "${GETHDATADIR}" --allow-insecure-unlock --unlock "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b" --password "" --nodiscover console
