# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import std/options
import stew/results
import ../beacon_chain/validators/fee_recipients
import "."/testutil

from std/tables import Table, len, `[]`
from web3/ethtypes import fromHex, `==`
from ../beacon_chain/spec/crypto import ValidatorPubKey, fromHex
from ../beacon_chain/spec/presets import Eth1Address

suite "Suggested fee recipients":
  setup:
    const
      feeRecipientList = """
default: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21
0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21
0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477: 0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"""
      feeRecipientListNoDefault = """
0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21
0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477: 0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d"""

  test "parseFeeRecipientList valid":
    let
      feeRecipients = parseFeeRecipientList(feeRecipientList)
      feeRecipientsNoDefault = parseFeeRecipientList(feeRecipientListNoDefault)
    check:
      feeRecipients.isOk
      feeRecipientsNoDefault.isOk
      feeRecipients.get()[default(ValidatorPubKey)] ==
        Eth1Address.fromHex("0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21")
      feeRecipientsNoDefault.get()[ValidatorPubKey.fromHex(
        "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007").get] ==
          Eth1Address.fromHex("0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21")
      feeRecipients.get()[ValidatorPubKey.fromHex(
        "0x87a580d31d7bc69069b55f5a01995a610dd391a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007").get] ==
          Eth1Address.fromHex("0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21")
      feeRecipientsNoDefault.get()[ValidatorPubKey.fromHex(
        "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get] ==
          Eth1Address.fromHex("0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d")
      feeRecipients.get()[ValidatorPubKey.fromHex(
        "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get] ==
          Eth1Address.fromHex("0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d")

  test "parseFeeRecipientList invalid":
    check:
      parseFeeRecipientList(
        "default 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21").isErr
      parseFeeRecipientList(
        "tluafed: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21").isErr

      # Not userful and indicates a probably incomplete setup.
      parseFeeRecipientList("").isErr

      # Invalid public key format
      parseFeeRecipientList(
        "0x87a580d31d7bc69069b55f5a01995a610dd31a26dc9e36e81057a17211983a79266800ab8531f21f1083d7d84085007: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21").isErr

      # Duplicate validator public keys
      parseFeeRecipientList("""
default: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21
default: 0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21""").isErr

      # Invalid suggested fee recipient
      parseFeeRecipientList("default: 0x6cc8dcbca744a6e4ffedb981d0df903b10abd21").isErr

  test "getFeeRecipient":
    check:
      # Ultimately, have to provide some Eth1Address, even if it's not useful
      getFeeRecipient(
        none(Eth1Address),
        parseFeeRecipientList(feeRecipientListNoDefault).get,
        default(ValidatorPubKey)) == default(Eth1Address)

      # No `--suggested-fee-recipient`, only `--suggested-fee-recipient-file`,
      # without a default.
      getFeeRecipient(
        none(Eth1Address),
        parseFeeRecipientList(feeRecipientListNoDefault).get,
        ValidatorPubKey.fromHex(
          "0xa5566f9ec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get) ==
            Eth1Address.fromHex("0xa2e334e71511686bcfe38bb3ee1ad8f6babcc03d")

      # No `--suggested-fee-recipient`, only `--suggested-fee-recipient-file`,
      # with a default, here triggered.
      getFeeRecipient(
        none(Eth1Address),
        parseFeeRecipientList(feeRecipientList).get,
        ValidatorPubKey.fromHex(
          "0xaaaaaaaec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get) ==
            Eth1Address.fromHex("0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21")

      # `--suggested-fee-recipient` and `--suggested-fee-recipient-file`, with
      # a default, which overrides distinct --suggested-fee-recipient.
      getFeeRecipient(
        some(Eth1Address.fromHex("eb80307cb67366e21ab5df8af1f3f37da8094cb0")),
        parseFeeRecipientList(feeRecipientList).get,
        ValidatorPubKey.fromHex(
          "0xaaaaaaaec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get) ==
            Eth1Address.fromHex("0x6cc8dcbca744a6e4ffedb98e1d0df903b10abd21")

      # `--suggested-fee-recipient` and `--suggested-fee-recipient-file`, with
      # no default, so distinct --suggested-fee-recipient is used.
      getFeeRecipient(
        some(Eth1Address.fromHex("0xeb80307cb67366e21ab5df8af1f3f37da8094cb0")),
        parseFeeRecipientList(feeRecipientListNoDefault).get,
        ValidatorPubKey.fromHex(
          "0xaaaaaaaec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get) ==
            Eth1Address.fromHex("0xeb80307cb67366e21ab5df8af1f3f37da8094cb0")

      # `--suggested-fee-recipient` but no `--suggested-fee-recipient-file`, so
      # use `--suggested-fee-recipient`
      getFeeRecipient(
        some(Eth1Address.fromHex("0xeb80307cb67366e21ab5df8af1f3f37da8094cb0")),
        static(default(FeeRecipientTable)),
        ValidatorPubKey.fromHex(
          "0xaaaaaaaec3c6e1fdf362634ebec9ef7aceb0e460e5079714808388e5d48f4ae1e12897fed1bea951c17fa389d511e477").get) ==
            Eth1Address.fromHex("0xeb80307cb67366e21ab5df8af1f3f37da8094cb0")
