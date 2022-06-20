# Import your validator keys into Nimbus

To import your signing key(s) into Nimbus, copy the `validator_keys` directory -- the directory that was created for you when you generated your keys using the [command line app](https://github.com/ethereum/eth2.0-deposit-cli) -- into `nimbus-eth2`. Then run:

**Prater**
```sh
build/nimbus_beacon_node deposits import --data-dir=build/data/shared_prater_0
```

**Mainnet**
```sh
build/nimbus_beacon_node deposits import --data-dir=build/data/shared_mainnet_0
```

>**Note:** You can also specify a different path to your `validator_keys` directory as follows:
>
>*Prater*
>```
>build/nimbus_beacon_node deposits import \
> --data-dir=build/data/shared_prater_0 "<YOUR VALIDATOR KEYS DIRECTORY>"
> ```
>
> *Mainnet*
> ```
>build/nimbus_beacon_node deposits import \
> --data-dir=build/data/shared_mainnet_0 "<YOUR VALIDATOR KEYS DIRECTORY>"
>```
>
> Replacing `<YOUR VALIDATOR KEYS DIRECTORY>` with the full pathname of the `validator_keys` directory that was created when you generated your keys using the [command line app](https://github.com/ethereum/eth2.0-deposit-cli/releases/).

 > **Tip:** You can run `pwd` in your `validator_keys` directory to print the full pathname to the console (if you're on Windows, run `cd` instead).


 You'll be asked to enter the password you created to encrypt your keystore(s).

 Don't worry, this is entirely normal. Your validator client needs both your signing keystore(s) and the password encrypting it to import your [key](https://blog.ethereum.org/2020/05/21/keys/) (since it needs to decrypt the keystore in order to be able to use it to sign on your behalf).

 >**Note:** If you come across an error, it's probably because the wrong permissions have been set on either a folder or file. See [here](faq.md#folder-permissions) for how to fix this.


## Storage

When you import your keys into Nimbus, your validator signing key(s) are stored in the `build/data/shared_<prater or mainnet>_0/` folder, under `secrets` and `validators` - **make sure you keep these folders backed up somewhere safe.**

 The `secrets` folder contains the common secret that gives you access to all your validator keys.

 The `validators` folder contains your signing keystore(s) (encrypted keys). Keystores are used by validators as a method for exchanging keys. For more on keys and keystores, see [here](https://blog.ethereum.org/2020/05/21/keys/).

 >**Note:** The Nimbus client will only ever import your signing key. In any case, if you used the deposit launchpad, this is the only key you should have (thanks to the way these keys are derived, it is possible to generate the withdrawal key from your mnemonic when you wish to withdraw).

## Export

*Todo*
