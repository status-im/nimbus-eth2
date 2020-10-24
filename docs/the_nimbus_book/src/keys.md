# Manage your keys

## Storage 

Your validator signing key(s) are stored in the `build/data/shared_medalla_0/` folder, under `secrets` and `validators` - make sure you keep these folders backed up.
 
 The `secrets` folder contains the common secret that gives you access to all your validator keys.
 
 The `validators` folder contains your signing keystore(s) (encrypted keys). Keystores are used by validators as a method for exchanging keys. For more on keys and keystores, see [here](https://blog.ethereum.org/2020/05/21/keys/).
 
 >**Note:** The Nimbus client will only ever import your signing key -- in any case, if you used the deposit launchpad, this is the only key you should have (thanks to the way these keys are derived, you can generate the withdrawal key from your mnemonic whenever you wish to withdraw).
 
 ## Import
 
 ## Export

