import
  std/macros,
  chronos, presto/client,
  ../beacon_chain/spec/mev/rest_bellatrix_mev_calls

from std/times import epochTime
from stew/byteutils import fromHex
from ../beacon_chain/beacon_clock import BeaconClock, init, now
from ../beacon_chain/networking/network_metadata import
  ropstenMetadata, sepoliaMetadata
from ../beacon_chain/spec/datatypes/bellatrix import SignedBeaconBlock
from ../beacon_chain/spec/eth2_apis/rest_beacon_calls import getBlockV2
from ../beacon_chain/spec/helpers import compute_domain, compute_signing_root

type NetworkInfo = object
  genesisTime: uint64
  restUrl: string
  runtimeConfig: RuntimeConfig
  genesisValidatorsRoot: Eth2Digest
  builderSigningDomain: Eth2Domain
  proposerSigningDomain: Eth2Domain

const
  feeRecipient =
    ExecutionAddress.fromHex("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b")
  ropstenInfo = NetworkInfo(
    genesisTime: 1653922800,
    restUrl: "https://builder-relay-ropsten.flashbots.net/",
    runtimeConfig: ropstenMetadata.cfg,
    genesisValidatorsRoot: Eth2Digest.fromHex(
      "0x44f1e56283ca88b35c789f7f449e52339bc1fefe3a45913a43a6d16edcd33cf1"),
    builderSigningDomain: Eth2Domain.fromHex(
      "0x00000001d5531fd3f3906407da127817ef33c71868154c6021bdaac6866406d8"),
    proposerSigningDomain: Eth2Domain.fromHex(
      "0x000000003cfa3bacace47d41ee4e3e7f989ed9c7e3e10904d2d67b36f1fda0b5")
  )
  sepoliaInfo = NetworkInfo(
    genesisTime: 1655733600,
    restUrl: "https://builder-relay-sepolia.flashbots.net/",
    runtimeConfig: sepoliaMetadata.cfg,
    genesisValidatorsRoot: Eth2Digest.fromHex(
      "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
    builderSigningDomain: Eth2Domain.fromHex(
      "0x00000001d3010778cd08ee514b08fe67b6c503b510987a4ce43f42306d97c67c"),
    proposerSigningDomain: Eth2Domain.fromHex(
      "0x0000000036fa50131482fe2af396daf210839ea6dcaaaa6372e95478610d7e08")
  )

proc getValidatorRegistration(
    forkVersion: Version, builderSigningDomain: Eth2Domain, timestamp: uint64,
    pubkey: ValidatorPubKey, privkey: ValidatorPrivKey):
    SignedValidatorRegistrationV1 =
  var validatorRegistration = SignedValidatorRegistrationV1(
    message: ValidatorRegistrationV1(
      fee_recipient: feeRecipient,
      gas_limit: 20000000,
      timestamp: timestamp,
      pubkey: pubkey))

  let domain = compute_domain(DOMAIN_APPLICATION_BUILDER, forkVersion)
  doAssert domain == builderSigningDomain
  let signingRoot = compute_signing_root(validatorRegistration.message, domain)

  validatorRegistration.signature =
    blsSign(privkey, signingRoot.data).toValidatorSig
  validatorRegistration

proc main(networkInfo: NetworkInfo) {.async.} =
  let
    restClient = RestClientRef.new(networkInfo.restUrl).get
    localClient = RestClientRef.new("http://127.0.0.1:5052").get
    privKey = ValidatorPrivKey.init(
      "0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06")
    pubKey = privKey.toPubKey.toPubKey

  # Builder status sanity check
  doAssert (await restClient.checkBuilderStatus()).status == 200

  # Validator registration
  let validatorRegistration = getValidatorRegistration(
    networkInfo.runtimeConfig.GENESIS_FORK_VERSION,
    networkInfo.builderSigningDomain, epochTime().uint64, pubkey, privkey)
  doAssert 200 ==
    (await restClient.registerValidator(@[validatorRegistration])).status

  # For getHeader, need previous block's hash, to build on
  let
    beaconClock = BeaconClock.init(networkInfo.genesis_time)
    curSlot = beaconClock.now.toSlot.slot

  echo "curSlot = ", curSlot
  let latestBlock = await localClient.getBlockV2(
    BlockIdent(kind: BlockQueryKind.Slot, slot: curSlot),
    networkInfo.runtimeConfig)
  doAssert latestBlock.isSome
  let bh =
    (latestBlock.get)[].bellatrixData.message.body.execution_payload.block_hash
  doAssert bh != default(Eth2Digest)

  # Get blinded execution header
  let blindedHeader = await restClient.getHeader(curSlot + 1, bh, pubKey)
  if blindedHeader.status != 200:
    echo "blindedHeader = ", blindedHeader
  doAssert blindedHeader.status == 200

  var blck: SignedBlindedBeaconBlock
  blck.message.slot = beaconClock.now.toSlot.slot + 1
  blck.message.proposer_index = 100
  blck.message.parent_root =
    hash_tree_root((latestBlock.get)[].bellatrixData.message)
  blck.message.state_root = blck.message.parent_root
  blck.message.body.execution_payload_header =
    blindedHeader.data.data.message.header

  let proposerSigningDomain = compute_domain(
    DOMAIN_BEACON_PROPOSER, networkInfo.runtimeConfig.BELLATRIX_FORK_VERSION,
    genesis_validators_root = networkInfo.genesisValidatorsRoot)
  doAssert proposerSigningDomain == networkInfo.proposerSigningDomain

  blck.signature = blsSign(
    privKey, compute_signing_root(
      hash_tree_root(blck.message), proposerSigningDomain).data).toValidatorSig

  let submitBlindedBlockResponse =
    await restClient.submitBlindedBlock(blck)

  if submitBlindedBlockResponse.status != 200:
    echo submitBlindedBlockResponse
  doAssert submitBlindedBlockResponse.status == 200
  doAssert submitBlindedBlockResponse.data.data is ExecutionPayload

  macro copyExecutionPayloadFields(a, b: untyped) =
    result = newStmtList()
    for name, value in fieldPairs(blck.message.body.execution_payload_header):
      if name != "transactions_root":
        result.add newAssignment(
          newDotExpr(a, ident(name)), newDotExpr(b, ident(name)))

  var fullBlck: bellatrix.SignedBeaconBlock
  fullBlck.signature = blck.signature
  copyExecutionPayloadFields(
    fullBlck.message.body.execution_payload,
    blck.message.body.execution_payload_header)
  fullBlck.message.body.execution_payload.transactions =
    submitBlindedBlockResponse.data.data.transactions

  doAssert hash_tree_root(fullBlck.message.body.execution_payload) ==
    hash_tree_root(blck.message.body.execution_payload_header)

  echo fullBlck.message.body.execution_payload
  echo submitBlindedBlockResponse.data.data

waitFor main(sepoliaInfo)
