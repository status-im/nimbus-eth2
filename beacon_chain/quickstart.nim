import
  stint, stew/endians2,
  spec/[crypto, digest, datatypes], conf, ssz

func quickStartValidators*(n: uint64): seq[ValidatorKeyPair] =
  let curveOrder = parse("52435875175126190479447740508185965837690552500527637822603658699938581184513", UInt256)

  for i in uint64(0) ..< n:
    var
      leBytes = i.toBytesLE()
      paddedBytes: array[32, byte]
      validator: ValidatorKeyPair

    copyMem(addr paddedBytes[0], addr leBytes[0], sizeof(leBytes))
    var hash = eth2hash(paddedBytes)
    validator.privKey.initFromBytes hash.data
    validator.pubKey = validator.privKey.pubKey

    result.add validator

func quickStartDeposits*(validators: openarray[ValidatorKeyPair]): seq[Deposit] =
  for validator in validators:
    var withdrawalCredentials = eth2hash(validator.pubKey.getBytes)
    withdrawalCredentials.data[0] = BLS_WITHDRAWAL_PREFIX

    var d = Deposit(
      data: DepositData(
        amount: MAX_EFFECTIVE_BALANCE,
        pubkey: validator.pubKey,
        withdrawal_credentials: withdrawalCredentials))

    d.data.signature =
      bls_sign(validator.privKey, signing_root(d.data).data, 3'u64)

    result.add d

func quickStartEth1Data*: Eth1Data =
  for i in 0 ..< result.block_hash.data.len:
    result.block_hash.data[i] = byte(0x42)

