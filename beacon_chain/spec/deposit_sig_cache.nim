# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  ./datatypes/[base, electra],
  ./eth2_merkleization

from ./helpers import is_builder_withdrawal_credential
from ./signatures import verify_deposit_signature

var depositSigValidity {.threadvar.}: Table[Eth2Digest, bool]

func depositSigKey(deposit: DepositData): Eth2Digest =
  hash_tree_root(deposit)

func verify_deposit_signature_cached*(
    genesis_fork_version: Version, deposit: DepositData): bool =
  {.cast(noSideEffect).}:
    let key = depositSigKey(deposit)
    depositSigValidity.withValue(key, v):
      return v[]
    let ok = verify_deposit_signature(genesis_fork_version, deposit)
    depositSigValidity[key] = ok
    ok

proc cacheBuilderDepositSigs*[N: static Limit](
    genesis_fork_version: Version, deposits: List[DepositRequest, N]) =
  for d in deposits:
    if not is_builder_withdrawal_credential(d.withdrawal_credentials):
      continue
    let
      dd = DepositData(
        pubkey: d.pubkey,
        withdrawal_credentials: d.withdrawal_credentials,
        amount: d.amount,
        signature: d.signature)
      key = depositSigKey(dd)
    if key notin depositSigValidity:
      depositSigValidity[key] = verify_deposit_signature(genesis_fork_version, dd)

proc clearBuilderDepositSigCache*() =
  reset(depositSigValidity)
