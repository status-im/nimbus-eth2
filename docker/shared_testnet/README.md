## local testing

From the "nim-beacon-chain" dir:

```text
make -C docker/shared_testnet build
mkdir tmp
docker run --rm --mount type=bind,source="$(pwd)"/tmp,target=/root/.cache/nimbus --name testnet2 statusteam/nimbus_beacon_node:testnet2 --build
ls -l tmp/nim-beacon-chain/build
docker run --rm --mount type=bind,source="$(pwd)"/tmp,target=/root/.cache/nimbus --name testnet2 -p 127.0.0.1:8008:8008 -p 9000:9000 statusteam/nimbus_beacon_node:testnet2 --run -- --metrics-address=0.0.0.0
# from another terminal
docker ps
docker stop testnet2
```

