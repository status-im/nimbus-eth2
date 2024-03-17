{.push raises: [].}

import
  std/[json, options],
  chronos, bearssl/rand, confutils, stint, json_serialization,
  web3, eth/keys, eth/p2p/discoveryv5/random2,
  stew/[io2, byteutils], json_rpc/jsonmarshal,
  ../beacon_chain/conf,
  ../beacon_chain/spec/eth2_merkleization,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/validators/keystore_management

from std/os import changeFileExt, fileExists
from std/times import toUnix
from ../beacon_chain/spec/beaconstate import initialize_beacon_state_from_eth1

# For nim-confutils, which uses this kind of init(Type, value) pattern
func init(T: type IpAddress, ip: IpAddress): T = ip

const mockEth1BlockHash* =
  Eth2Digest.fromHex("0x4242424242424242424242424242424242424242")
type
  Eth1Address = web3.Address

  StartUpCommand {.pure.} = enum
    createTestnet

  CliConfig* = object
    web3Url* {.
      defaultValue: "",
      desc: "URL of the Web3 server to observe Eth1"
      name: "web3-url" }: string

    privateKey* {.
      defaultValue: ""
      desc: "Private key of the controlling account"
      name: "private-key" }: string

    askForKey* {.
      defaultValue: false
      desc: "Ask for an Eth1 private key interactively"
      name: "ask-for-key" }: bool

    eth2Network* {.
      desc: "The Eth2 network preset to use"
      name: "network" }: Option[string]

    case cmd* {.command.}: StartUpCommand
    of StartUpCommand.createTestnet:
      testnetDepositsFile* {.
        desc: "A LaunchPad deposits file for the genesis state validators"
        name: "deposits-file" .}: InputFile

      totalValidators* {.
        desc: "The number of validator deposits in the newly created chain"
        name: "total-validators" .}: uint64

      bootstrapPort* {.
        desc: "The TCP/UDP port that will be used by the bootstrap node"
        defaultValue: defaultEth2TcpPort
        defaultValueDesc: $defaultEth2TcpPortDesc
        name: "bootstrap-port" .}: Port

      dataDir* {.
        desc: "Nimbus data directory where the keys of the bootstrap node will be placed"
        name: "data-dir" .}: OutDir

      netKeyFile* {.
        desc: "Source of network (secp256k1) private key file"
        name: "netkey-file" .}: OutFile

      netKeyInsecurePassword* {.
        desc: "Use pre-generated INSECURE password for network private key file"
        defaultValue: false,
        name: "insecure-netkey-password" .}: bool

      genesisTime* {.
        desc: "Unix epoch time of the network genesis"
        name: "genesis-time" .}: Option[uint64]

      genesisOffset* {.
        desc: "Seconds from now to add to genesis time"
        name: "genesis-offset" .}: Option[int]

      executionGenesisBlock* {.
        desc: "The execution genesis block in a merged testnet"
        name: "execution-genesis-block" .}: Option[InputFile]

      capellaForkEpoch* {.
        defaultValue: FAR_FUTURE_EPOCH
        desc: "The epoch of the Capella hard-fork"
        name: "capella-fork-epoch" .}: Epoch

      denebForkEpoch* {.
        defaultValue: FAR_FUTURE_EPOCH
        desc: "The epoch of the Deneb hard-fork"
        name: "deneb-fork-epoch" .}: Epoch

      outputGenesis* {.
        desc: "Output file where to write the initial state snapshot"
        name: "output-genesis" .}: OutFile

      outputDepositTreeSnapshot* {.
        desc: "Output file where to write the initial deposit tree snapshot"
        name: "output-deposit-tree-snapshot" .}: OutFile

      outputBootstrapFile* {.
        desc: "Output file with list of bootstrap nodes for the network"
        name: "output-bootstrap-file" .}: OutFile

type
  PubKeyBytes = DynamicBytes[48, 48]
  WithdrawalCredentialsBytes = DynamicBytes[32, 32]
  SignatureBytes = DynamicBytes[96, 96]

contract(DepositContract):
  proc deposit(pubkey: PubKeyBytes,
               withdrawalCredentials: WithdrawalCredentialsBytes,
               signature: SignatureBytes,
               deposit_data_root: FixedBytes[32])

from ".."/beacon_chain/spec/datatypes/bellatrix import BloomLogs, ExecutionAddress

template `as`(address: Eth1Address, T: type bellatrix.ExecutionAddress): T =
  T(data: distinctBase(address))

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

template `as`(address: BlockHash, T: type Eth2Digest): T =
  asEth2Digest(address)

func getOrDefault[T](x: Option[T]): T =
  if x.isSome:
    x.get
  else:
    default T

func `as`(blk: BlockObject, T: type bellatrix.ExecutionPayloadHeader): T =
  T(parent_hash: blk.parentHash as Eth2Digest,
    fee_recipient: blk.miner as ExecutionAddress,
    state_root: blk.stateRoot as Eth2Digest,
    receipts_root: blk.receiptsRoot as Eth2Digest,
    logs_bloom: BloomLogs(data: distinctBase(blk.logsBloom)),
    prev_randao: Eth2Digest(data: blk.difficulty.toByteArrayBE), # Is BE correct here?
    block_number: uint64 blk.number,
    gas_limit: uint64 blk.gasLimit,
    gas_used: uint64 blk.gasUsed,
    timestamp: uint64 blk.timestamp,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(blk.extraData.bytes),
    base_fee_per_gas: blk.baseFeePerGas.getOrDefault(),
    block_hash: blk.hash as Eth2Digest,
    transactions_root: blk.transactionsRoot as Eth2Digest)

from ".."/beacon_chain/spec/datatypes/capella import ExecutionPayloadHeader

func `as`(blk: BlockObject, T: type capella.ExecutionPayloadHeader): T =
  T(parent_hash: blk.parentHash as Eth2Digest,
    fee_recipient: blk.miner as ExecutionAddress,
    state_root: blk.stateRoot as Eth2Digest,
    receipts_root: blk.receiptsRoot as Eth2Digest,
    logs_bloom: BloomLogs(data: distinctBase(blk.logsBloom)),
    prev_randao: Eth2Digest(data: blk.difficulty.toByteArrayBE),
    block_number: uint64 blk.number,
    gas_limit: uint64 blk.gasLimit,
    gas_used: uint64 blk.gasUsed,
    timestamp: uint64 blk.timestamp,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(blk.extraData.bytes),
    base_fee_per_gas: blk.baseFeePerGas.getOrDefault(),
    block_hash: blk.hash as Eth2Digest,
    transactions_root: blk.transactionsRoot as Eth2Digest,
    withdrawals_root: blk.withdrawalsRoot.getOrDefault() as Eth2Digest)

from ".."/beacon_chain/spec/datatypes/deneb import ExecutionPayloadHeader

func `as`(blk: BlockObject, T: type deneb.ExecutionPayloadHeader): T =
  T(parent_hash: blk.parentHash as Eth2Digest,
    fee_recipient: blk.miner as ExecutionAddress,
    state_root: blk.stateRoot as Eth2Digest,
    receipts_root: blk.receiptsRoot as Eth2Digest,
    logs_bloom: BloomLogs(data: distinctBase(blk.logsBloom)),
    prev_randao: Eth2Digest(data: blk.difficulty.toByteArrayBE),
    block_number: uint64 blk.number,
    gas_limit: uint64 blk.gasLimit,
    gas_used: uint64 blk.gasUsed,
    timestamp: uint64 blk.timestamp,
    extra_data: List[byte, MAX_EXTRA_DATA_BYTES].init(blk.extraData.bytes),
    base_fee_per_gas: blk.baseFeePerGas.getOrDefault(),
    block_hash: blk.hash as Eth2Digest,
    transactions_root: blk.transactionsRoot as Eth2Digest,
    withdrawals_root: blk.withdrawalsRoot.getOrDefault() as Eth2Digest,
    blob_gas_used: uint64 blk.blobGasUsed.getOrDefault(),
    excess_blob_gas: uint64 blk.excessBlobGas.getOrDefault())

from ".."/beacon_chain/spec/deposit_snapshots import DepositTreeSnapshot

func createDepositTreeSnapshot(deposits: seq[DepositData],
                               blockHash: Eth2Digest,
                               blockHeight: uint64): DepositTreeSnapshot =
  var merkleizer = DepositsMerkleizer.init()
  for i, deposit in deposits:
    let htr = hash_tree_root(deposit)
    merkleizer.addChunk(htr.data)

  DepositTreeSnapshot(
    eth1Block: blockHash,
    depositContractState: merkleizer.toDepositContractState,
    blockHeight: blockHeight)

import ssz_serialization
import ".."/beacon_chain/extras
import ".."/beacon_chain/spec/ssz_codec

proc doCreateTestnet*(config: CliConfig,
                      rng: var HmacDrbgContext)
                     {.raises: [CatchableError].} =
  let launchPadDeposits = try:
    Json.loadFile(config.testnetDepositsFile.string, seq[LaunchPadDeposit])
  except SerializationError as err:
    quit 1

  var deposits: seq[DepositData]
  for i in 0 ..< launchPadDeposits.len:
    deposits.add(launchPadDeposits[i] as DepositData)

  let
    startTime = if config.genesisTime.isSome:
      config.genesisTime.get
    else:
      uint64(times.toUnix(times.getTime()) + config.genesisOffset.get(0))
    outGenesis = config.outputGenesis.string
    eth1Hash = mockEth1BlockHash # TODO: Can we set a more appropriate value?
    cfg = getRuntimeConfig(config.eth2Network)

  # This is intentionally left default initialized, when the user doesn't
  # provide an execution genesis block. The generated genesis state will
  # then be considered non-finalized merged state according to the spec.
  var genesisBlock = BlockObject()

  if config.executionGenesisBlock.isSome:
    if not fileExists(config.executionGenesisBlock.get.string):
      quit 1

    let genesisBlockContents = readAllChars(config.executionGenesisBlock.get.string)
    if genesisBlockContents.isErr:
      quit 1

    try:
      let blockAsJson = genesisBlockContents.get
      genesisBlock = JrpcConv.decode(blockAsJson, BlockObject)
    except CatchableError as err:
      quit 1

  template createAndSaveState(genesisExecutionPayloadHeader: auto): Eth2Digest =
    var initialState = newClone(initialize_beacon_state_from_eth1(
        cfg, eth1Hash, startTime, deposits, genesisExecutionPayloadHeader,
        {skipBlsValidation}))
    # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
    initialState.genesis_time = startTime

    doAssert initialState.validators.len > 0

    let outSszGenesis = outGenesis.changeFileExt "ssz"
    SSZ.saveFile(outSszGenesis, initialState[])
    SSZ.saveFile(
      config.outputDepositTreeSnapshot.string,
      createDepositTreeSnapshot(
        deposits,
        genesisExecutionPayloadHeader.block_hash,
        genesisExecutionPayloadHeader.block_number))

    initialState[].genesis_validators_root

  let genesisValidatorsRoot =
    if config.denebForkEpoch == 0:
      createAndSaveState(genesisBlock as deneb.ExecutionPayloadHeader)
    elif config.capellaForkEpoch == 0:
      createAndSaveState(genesisBlock as capella.ExecutionPayloadHeader)
    else:
      createAndSaveState(genesisBlock as bellatrix.ExecutionPayloadHeader)
