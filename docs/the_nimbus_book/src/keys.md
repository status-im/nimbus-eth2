# Import your keys


> ⚠️  This page concerns the Medalla testnet only. If you have made a mainnet deposit, you do not need to import your keys into Nimbus quite yet. 


To import your signing key(s) into Nimbus, from the `nimbus-eth2` directory run:

```
 build/beacon_node deposits import  --data-dir=build/data/shared_medalla_0 <YOUR VALIDATOR KEYS DIRECTORY>
 ```
 
 
 Replacing `<YOUR VALIDATOR KEYS DIRECTORY>` with the full pathname of the `validator_keys` directory that was created when you generated your keys using the [Medalla Launchpad](https://medalla.launchpad.ethereum.org/) [command line app](https://github.com/ethereum/eth2.0-deposit-cli/releases/).
 
 > **Tip:** run `pwd` in your `validator_keys` directory to print the full pathname to the console.
 
 You'll be asked to enter the password you created to encrypt your keystore(s).
 
 Don't worry, this is entirely normal. Your validator client needs both your signing keystore(s) and the password encrypting it to import your [key](https://blog.ethereum.org/2020/05/21/keys/) (since it needs to decrypt the keystore in order to be able to use it to sign on your behalf).

## Storage 

When you import your keys into Nimbus, your validator signing key(s) are stored in the `build/data/shared_medalla_0/` folder, under `secrets` and `validators` - **make sure you keep these folders backed up somewhere sage.**
 
 The `secrets` folder contains the common secret that gives you access to all your validator keys.
 
 The `validators` folder contains your signing keystore(s) (encrypted keys). Keystores are used by validators as a method for exchanging keys. For more on keys and keystores, see [here](https://blog.ethereum.org/2020/05/21/keys/).
 
 >**Note:** The Nimbus client will only ever import your signing key -- in any case, if you used the deposit launchpad, this is the only key you should have (thanks to the way these keys are derived, you can generate the withdrawal key from your mnemonic whenever you wish to withdraw).
  
## Export

*Todo*
