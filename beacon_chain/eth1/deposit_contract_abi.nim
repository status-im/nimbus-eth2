import
  web3, web3/ethtypes

export
  web3, ethtypes

type
  PubKeyBytes* = DynamicBytes[48, 48]
  WithdrawalCredentialsBytes* = DynamicBytes[32, 32]
  SignatureBytes* = DynamicBytes[96, 96]
  Int64LeBytes* = DynamicBytes[8, 8]

contract(DepositContract):
  proc deposit(pubkey: PubKeyBytes,
               withdrawalCredentials: WithdrawalCredentialsBytes,
               signature: SignatureBytes,
               deposit_data_root: FixedBytes[32])

  proc get_deposit_root(): FixedBytes[32]
  proc get_deposit_count(): Int64LeBytes

  proc DepositEvent(pubkey: PubKeyBytes,
                    withdrawalCredentials: WithdrawalCredentialsBytes,
                    amount: Int64LeBytes,
                    signature: SignatureBytes,
                    index: Int64LeBytes) {.event.}
