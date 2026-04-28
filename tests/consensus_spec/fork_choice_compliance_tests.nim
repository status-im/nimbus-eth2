# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

# Standalone entry point for the consensus-specs fork-choice compliance suite
# (see scripts/setup_fork_choice_compliance.sh). Avoids pulling in the full
# consensus_spec_tests_preset binary, which requires the complete
# nim-eth2-scenarios test vectors to be installed.

import
  ../testutil,
  ./test_fixture_fork_choice

summarizeLongTests("ForkChoiceCompliance")
