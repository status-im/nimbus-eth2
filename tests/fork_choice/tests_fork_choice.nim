# Don't forgot to run the following files as main modules:
# - beacon_chain/fork_choice/proto_array.nim (sanity checks for tiebreak)
# - beacon_chain/fork_choice/fork_choice.nim (sanity checks for compute_deltas)

{.used.}

import ../testutil

# include to be able to use "suite"
import ./interpreter
suite "Fork Choice + Finality " & preset():
  include scenarios/[no_votes, votes, ffg_01, ffg_02]
