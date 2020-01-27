import
  stew/endians2, stint,
  ./extras, ./ssz,
  spec/[crypto, datatypes, digest, helpers]

func get_eth1data_stub*(deposit_count: uint64, current_epoch: Epoch): Eth1Data =
  # https://github.com/ethereum/eth2.0-pm/blob/e596c70a19e22c7def4fd3519e20ae4022349390/interop/mocked_eth1data/README.md
  let
    epochs_per_period = SLOTS_PER_ETH1_VOTING_PERIOD div SLOTS_PER_EPOCH
    voting_period = current_epoch.uint64 div epochs_per_period.uint64

  Eth1Data(
    deposit_root: hash_tree_root(voting_period),
    deposit_count: deposit_count,
    block_hash: hash_tree_root(hash_tree_root(voting_period).data),
  )

when ValidatorPrivKey is BlsValue:
  func makeInteropPrivKey*(i: int): ValidatorPrivKey =
    discard
    {.fatal: "todo/unused?".}
else:
  func makeInteropPrivKey*(i: int): ValidatorPrivKey =
    var bytes: array[32, byte]
    bytes[0..7] = uint64(i).toBytesLE()

    let
      # BLS381-12 curve order - same as milagro but formatted different
      curveOrder =
        "52435875175126190479447740508185965837690552500527637822603658699938581184513".parse(UInt256)

      privkeyBytes = eth2hash(bytes)
      key = (UInt256.fromBytesLE(privkeyBytes.data) mod curveOrder).toBytesBE()

    ValidatorPrivKey.init(key)

const eth1BlockHash* = block:
  var x: Eth2Digest
  for v in x.data.mitems: v = 0x42
  x

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/deposit-contract.md#withdrawal-credentials
func makeWithdrawalCredentials*(k: ValidatorPubKey): Eth2Digest =
  var bytes = eth2hash(k.getBytes())
  bytes.data[0] = BLS_WITHDRAWAL_PREFIX.uint8
  bytes

func makeDeposit*(
    pubkey: ValidatorPubKey, privkey: ValidatorPrivKey, epoch = 0.Epoch,
    amount: Gwei = MAX_EFFECTIVE_BALANCE.Gwei,
    flags: UpdateFlags = {}): Deposit =
  var
    ret = Deposit(
      data: DepositData(
        amount: amount,
        pubkey: pubkey,
        withdrawal_credentials: makeWithdrawalCredentials(pubkey)))

  if skipValidation notin flags:
    ret.data.signature =
      bls_sign(
        privkey, hash_tree_root(ret.getDepositMessage).data,
        compute_domain(DOMAIN_DEPOSIT))

  ret
