import
  os, strutils,
  chronicles, chronos, blscurve, nimcrypto, json_serialization, serialization,
  web3, stint, eth/keys,
  spec/[datatypes, digest, crypto], conf, ssz/merkleization, interop, merkle_minimal

contract(DepositContract):
  proc deposit(pubkey: Bytes48, withdrawalCredentials: Bytes32, signature: Bytes96, deposit_data_root: FixedBytes[32])

type
 DelayGenerator* = proc(): chronos.Duration {.closure, gcsafe.}

proc writeTextFile(filename: string, contents: string) =
  writeFile(filename, contents)
  # echo "Wrote ", filename

proc writeFile(filename: string, value: auto) =
  Json.saveFile(filename, value, pretty = true)
  # echo "Wrote ", filename

proc ethToWei(eth: UInt256): UInt256 =
  eth * 1000000000000000000.u256

proc generateDeposits*(totalValidators: int,
                       outputDir: string,
                       randomKeys: bool,
                       firstIdx = 0): seq[Deposit] =
  info "Generating deposits", totalValidators, outputDir, randomKeys
  for i in 0 ..< totalValidators:
    let
      v = validatorFileBaseName(firstIdx + i)
      depositFn = outputDir / v & ".deposit.json"
      privKeyFn = outputDir / v & ".privkey"

    if existsFile(depositFn) and existsFile(privKeyFn):
      try:
        result.add Json.loadFile(depositFn, Deposit)
        continue
      except SerializationError as err:
        debug "Rewriting unreadable deposit", err = err.formatMsg(depositFn)
        discard

    var
      privkey{.noInit.}: ValidatorPrivKey
      pubKey{.noInit.}: ValidatorPubKey

    if randomKeys:
      (pubKey, privKey) = crypto.newKeyPair().tryGet()
    else:
      privKey = makeInteropPrivKey(i).tryGet()
      pubKey = privKey.toPubKey()

    let dp = makeDeposit(pubKey, privKey)

    result.add(dp)

    # Does quadratic additional work, but fast enough, and otherwise more
    # cleanly allows free intermixing of pre-existing and newly generated
    # deposit and private key files. TODO: only generate new Merkle proof
    # for the most recent deposit if this becomes bottleneck.
    attachMerkleProofs(result)

    writeTextFile(privKeyFn, privKey.toHex())
    writeFile(depositFn, result[result.len - 1])

proc sendDeposits*(
    deposits: seq[Deposit],
    web3Url, depositContractAddress, privateKey: string,
    delayGenerator: DelayGenerator = nil) {.async.} =

  var web3 = await newWeb3(web3Url)
  if privateKey.len != 0:
    web3.privateKey = PrivateKey.fromHex(privateKey).tryGet()
  else:
    let accounts = await web3.provider.eth_accounts()
    if accounts.len == 0:
      error "No account offered by the web3 provider", web3Url
      return
    web3.defaultAccount = accounts[0]

  let contractAddress = Address.fromHex(depositContractAddress)

  for i, dp in deposits:
    let depositContract = web3.contractSender(DepositContract, contractAddress)
    discard await depositContract.deposit(
      Bytes48(dp.data.pubKey.toRaw()),
      Bytes32(dp.data.withdrawal_credentials.data),
      Bytes96(dp.data.signature.toRaw()),
      FixedBytes[32](hash_tree_root(dp.data).data)).send(value = 32.u256.ethToWei, gasPrice = 1)

    if delayGenerator != nil:
      await sleepAsync(delayGenerator())

when isMainModule:
  import confutils

  cli do (totalValidators: int = 125000,
          outputDir: string = "validators",
          randomKeys: bool = false,
          web3Url: string = "",
          depositContractAddress: string = ""):
    let deposits = generateDeposits(totalValidators, outputDir, randomKeys)

    if web3Url.len() > 0 and depositContractAddress.len() > 0:
      echo "Sending deposits to eth1..."
      waitFor sendDeposits(deposits, web3Url, depositContractAddress, "")
      echo "Done"
