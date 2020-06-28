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

## setting up remote servers

From the "infra-nimbus" repo:

```text
git pull
ansible-galaxy install -g -f -r ansible/requirements.yml
ansible-playbook ansible/nimbus.yml -i ansible/inventory/test -t beacon-node -u YOUR_USER -K -l nimbus-slaves[5:8]

# faster way to pull the Docker image and recreate the containers (this also stops any running container)
ansible nimbus-slaves[5:8] -i ansible/inventory/test -u YOUR_USER -o -m shell -a "echo; cd /docker/beacon-node-testnet2-1; docker-compose --compatibility pull; docker-compose --compatibility up --no-start; echo '---'" | sed 's/\\n/\n/g'

# build beacon_node in an external volume
ansible nimbus-slaves[5:8] -i ansible/inventory/test -u YOUR_USER -o -m shell -a "echo; cd /docker/beacon-node-testnet2-1; docker-compose --compatibility run --rm beacon_node --build; echo '---'" | sed 's/\\n/\n/g'
```

### create and copy validator keys

Back up "build/data/shared\_witti\_0", if you need to. It will be deleted.

From the nim-beacon-chain repo:

```bash
# If you have "ignorespace" or "ignoreboth" in HISTCONTROL in your ".bashrc", you can prevent
# the key from being stored in your command history by prefixing it with a space.
# See https://www.linuxjournal.com/content/using-bash-history-more-efficiently-histcontrol

 ./docker/shared_testnet/validator_keys.sh 0xYOUR_ETH1_PRIVATE_GOERLI_KEY
```

### start the containers

From the "infra-nimbus" repo:

```bash
ansible nimbus-slaves[5:8] -i ansible/inventory/test -u YOUR_USER -o -m shell -a "echo; cd /docker/beacon-node-testnet2-1; docker-compose --compatibility up -d; echo '---'" | sed 's/\\n/\n/g'
```

