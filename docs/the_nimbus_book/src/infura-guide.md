# Supplying your own Infura endpoint


In a nutshell, Infura is a hosted ethereum node cluster that lets you make requests to the eth1 blockchain without requiring you to set up your own eth1 node.

While we do support Infura to process incoming validator deposits, we recommend running your own eth1 node to avoid relying on a third-party-service.

> **Note:** Nimbus currently supports remote Infura nodes and [local Geth nodes](./eth1.md). In the future, we plan on having our own eth1 client -- [Nimbus 1](https://github.com/status-im/nimbus) -- be the recommended default.

### 1. Visit Infura.io

Go to:

[https://infura.io/](https://infura.io/)

and click on `Get Started For Free`

![](https://i.imgur.com/BtStgup.png)

### 2. Sign up

Enter your email address and create a password

![](https://i.imgur.com/al1OsdR.png)

### 3. Verify email address
You should have received an email from Infura in your inbox. Open up it up and click on `Confirm Email Address`

![](https://i.imgur.com/EAD8ZhV.png)

### 4. Go to dashboard
This will take you to your Infura dashboard (https://infura.io/dashboard/)

![](https://i.imgur.com/LuNcoYr.png)

### 5. Create your first project

Click on the first option (`create your first project`) under `Let's Get Started`

![](https://i.imgur.com/wBAGhcs.png)

Choose a name for your project

![](https://i.imgur.com/yr5vnSo.png)

You'll be directed to the settings page of your newly created project

![](https://i.imgur.com/kx3R8XS.png)

### 6. Select endpoint

> ⚠️  **Warning:** if you're connecting to mainnet, you should skip this step

If you're connecting to a testnet, in the `KEYS` section, click on the dropdown menu to the right of `ENDPOINTS`, and select `GÖRLI`

![](https://i.imgur.com/D9186kv.png)


### 7. Copy the websocket endpoint

Copy the address that starts with `wss://`

![](https://i.imgur.com/fZ6Bcjy.png)

> ⚠️  **Warning:** make sure you've copied the endpoint that starts with`wss` (websocket), and not the `https` endpoint. If you're connecting  to mainnet this will read `wss://mainnet.infura.io/ws/...`


### 8. Run the beacon node

[Launch the beacon node](./start-syncing.md) on your favourite testnet, pasaing in your websocket endpoint as the [Web3 provider URL](./start-syncing.md#web3-provider-url).



### 9. Check stats

Visit your project's stats page to see a summary of your eth1 related activity and method calls

![](https://i.imgur.com/MZVTHHV.png)

That's all there is to it :)
