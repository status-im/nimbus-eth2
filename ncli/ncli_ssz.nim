import
  confutils, os, strutils, json_serialization,
  stew/byteutils,
  ../beacon_chain/spec/[crypto, datatypes, digest],
  ../beacon_chain/ssz/[merkleization, ssz_serialization]

type
  Cmd* = enum
    hashTreeRoot = "Compute hash tree root of SSZ object"
    pretty = "Pretty-print SSZ object"

  NcliConf* = object
    # TODO confutils argument pragma doesn't seem to do much; also, the cases
    # are largely equivalent, but this helps create command line usage text
    case cmd* {.command}: Cmd
    of hashTreeRoot:
      htrKind* {.
        argument
        desc: "kind of SSZ object: attester_slashing, attestation, signed_block, block, block_body, block_header, deposit, deposit_data, eth1_data, state, proposer_slashing, or voluntary_exit"}: string

      htrFile* {.
        argument
        desc: "filename of SSZ or JSON-encoded object of which to compute hash tree root"}: string
    of pretty:
      prettyKind* {.
        argument
        desc: "kind of SSZ object: attester_slashing, attestation, signed_block, block, block_body, block_header, deposit, deposit_data, eth1_data, state, proposer_slashing, or voluntary_exit"}: string

      prettyFile* {.
        argument
        desc: "filename of SSZ or JSON-encoded object to pretty-print"}: string

when isMainModule:
  let conf = NcliConf.load()

  let (kind, file) =
    case conf.cmd:
    of hashTreeRoot: (conf.htrKind, conf.htrFile)
    of pretty: (conf.prettyKind, conf.prettyFile)

  template printit(t: untyped) {.dirty.} =
    let v = newClone(
      if cmpIgnoreCase(ext, ".ssz") == 0:
        SSZ.loadFile(file, t)
      elif cmpIgnoreCase(ext, ".json") == 0:
        JSON.loadFile(file, t)
      else:
        echo "Unknown file type: ", ext
        quit 1
    )

    case conf.cmd:
    of hashTreeRoot:
      when t is SignedBeaconBlock:
        echo hash_tree_root(v.message).data.toHex()
      else:
        echo hash_tree_root(v[]).data.toHex()
    of pretty:
      echo JSON.encode(v[], pretty = true)

  let ext = splitFile(file).ext

  case kind
  of "attester_slashing": printit(AttesterSlashing)
  of "attestation": printit(Attestation)
  of "signed_block": printit(SignedBeaconBlock)
  of "block": printit(BeaconBlock)
  of "block_body": printit(BeaconBlockBody)
  of "block_header": printit(BeaconBlockHeader)
  of "deposit": printit(Deposit)
  of "deposit_data": printit(DepositData)
  of "eth1_data": printit(Eth1Data)
  of "state": printit(BeaconState)
  of "proposer_slashing": printit(ProposerSlashing)
  of "voluntary_exit": printit(VoluntaryExit)
