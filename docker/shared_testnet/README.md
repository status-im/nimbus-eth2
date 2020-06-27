## local testing

From the "nim-beacon-chain" repo (top-level dir):

```text
make -C docker/shared_testnet build
mkdir tmp
docker run --rm --mount type=bind,source="$(pwd)"/tmp,target=/root/.cache/nimbus --name testnet2 statusteam/nimbus_beacon_node:testnet2 --build
ls -l tmp/nim-beacon-chain/build
docker run --rm --mount type=bind,source="$(pwd)"/tmp,target=/root/.cache/nimbus --name testnet2 -p 127.0.0.1:8008:8008 -p 9000:9000 statusteam/nimbus_beacon_node:testnet2 --run -- --metrics-address=0.0.0.0

# from another terminal
docker ps
docker stop testnet2

# when you're happy with the Docker image:
make -C docker/shared_testnet push
```

Setting up the remote servers, from the "infra-nimbus" repo:

```text
git pull
ansible-galaxy install -g -f -r ansible/requirements.yml
ansible-playbook ansible/nimbus.yml -i ansible/inventory/test -t beacon-node -u YOUR_USER -K -l nimbus-slaves[5:8]

# faster way to pull the Docker image and recreate the containers
ansible nimbus-slaves[5:8] -i ansible/inventory/test -u YOUR_USER -o -m shell -a "echo; cd /docker/beacon-node-testnet2-1; docker-compose --compatibility up --no-start beacon_node; echo '---'" | sed 's/\\n/\n/g'

# build beacon_node in an external volume
ansible nimbus-slaves[5:8] -i ansible/inventory/test -u YOUR_USER -o -m shell -a "echo; cd /docker/beacon-node-testnet2-1; docker-compose --compatibility run --rm beacon_node --build; echo '---'" | sed 's/\\n/\n/g'

# TODO: create and copy validator keys

# start the containers
ansible nimbus-slaves[5:8] -i ansible/inventory/test -u YOUR_USER -o -m shell -a "echo; cd /docker/beacon-node-testnet2-1; docker-compose --compatibility up -d beacon_node; echo '---'" | sed 's/\\n/\n/g'
```

