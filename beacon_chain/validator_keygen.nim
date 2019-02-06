import
  os, ospaths, strutils, strformat,
  chronos, nimcrypto, json_serialization, confutils,
  spec/[datatypes, digest, crypto], conf, randao, time, ssz,
  ../tests/testutil

proc writeFile(filename: string, value: auto) =
  Json.saveFile(filename, value, pretty = true)
  echo "Wrote ", filename

proc genSingleValidator(path: string): (ValidatorPubKey,
                                        ValidatorPrivKey,
                                        Eth2Digest) =
  var v: PrivateValidatorData
  # v.privKey = newSigKey()
  if randomBytes(v.randao.seed.data) != sizeof(v.randao.seed.data):
    raise newException(Exception, "Could not generate randao seed")

  writeFile(path, v)

  return (v.privKey.pubKey(), v.privKey, v.randao.initialCommitment)

# TODO: Make these more comprehensive and find them a new home
type
  Ether* = distinct int64
  GWei* = distinct int64

template eth*(x: SomeInteger): Ether = Ether(x)
template gwei*(x: Ether): Gwei = Gwei(int(x) * 1000000000)

cli do (validators: int,
        outputDir: string,
        startupDelay = 0):

  if validators < 64:
    echo "The number of validators must be higher than ", EPOCH_LENGTH, " (EPOCH_LENGTH)"
    echo "There must be at least one validator assigned per slot."
    quit 1

  var startupData: ChainStartupData

  for i in 1 .. validators:
    let (pubKey, privKey, randaoCommitment) =
      genSingleValidator(outputDir / &"validator-{i:02}.json")

    let
      withdrawalCredentials = makeFakeHash(i)

      proofOfPossessionData = DepositInput(
        pubkey: pubKey,
        withdrawal_credentials: withdrawalCredentials,
        randao_commitment: randaoCommitment)

      proofOfPossession = bls_sign(
        privkey, hash_tree_root_final(proofOfPossessionData).data,
        0 # TODO - domain
        )

    startupData.validatorDeposits.add Deposit(
      deposit_data: DepositData(
        amount: MAX_DEPOSIT_AMOUNT,
        timestamp: now(),
        deposit_input: DepositInput(
          pubkey: pubKey,
          proof_of_possession: proofOfPossession,
          withdrawal_credentials: withdrawalCredentials,
          randao_commitment: randaoCommitment)))

  startupData.genesisTime = uint64(int(now() div 1000) + startupDelay)

  writeFile(outputDir / "startup.json", startupData)

