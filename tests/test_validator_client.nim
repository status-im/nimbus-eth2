# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/strutils
import unittest2
import ../beacon_chain/validator_client/common

const
  HostNames = [
    "[2001:db8::1]",
    "127.0.0.1",
    "hostname.com",
    "localhost",
    "username:password@[2001:db8::1]",
    "username:password@127.0.0.1",
    "username:password@hostname.com",
    "username:password@localhost",
  ]

  GoodTestVectors = [
    ("http://$1",
     "ok(http://$1)"),
    ("http://$1?q=query",
     "ok(http://$1?q=query)"),
    ("http://$1?q=query#anchor",
     "ok(http://$1?q=query#anchor)"),
    ("http://$1/subpath/",
     "ok(http://$1/subpath/)"),
    ("http://$1/subpath/q=query",
     "ok(http://$1/subpath/q=query)"),
    ("http://$1/subpath/q=query#anchor",
     "ok(http://$1/subpath/q=query#anchor)"),
    ("http://$1/subpath",
     "ok(http://$1/subpath)"),
    ("http://$1/subpath?q=query",
     "ok(http://$1/subpath?q=query)"),
    ("http://$1/subpath?q=query#anchor",
     "ok(http://$1/subpath?q=query#anchor)"),

    ("https://$1",
     "ok(https://$1)"),
    ("https://$1?q=query",
     "ok(https://$1?q=query)"),
    ("https://$1?q=query#anchor",
     "ok(https://$1?q=query#anchor)"),
    ("https://$1/subpath/",
     "ok(https://$1/subpath/)"),
    ("https://$1/subpath/q=query",
     "ok(https://$1/subpath/q=query)"),
    ("https://$1/subpath/q=query#anchor",
     "ok(https://$1/subpath/q=query#anchor)"),
    ("https://$1/subpath",
     "ok(https://$1/subpath)"),
    ("https://$1/subpath?q=query",
     "ok(https://$1/subpath?q=query)"),
    ("https://$1/subpath?q=query#anchor",
     "ok(https://$1/subpath?q=query#anchor)"),

    ("$1:5052",
     "ok(http://$1:5052)"),
    ("$1:5052?q=query",
     "ok(http://$1:5052?q=query)"),
    ("$1:5052?q=query#anchor",
     "ok(http://$1:5052?q=query#anchor)"),
    ("$1:5052/subpath/",
     "ok(http://$1:5052/subpath/)"),
    ("$1:5052/subpath/q=query",
     "ok(http://$1:5052/subpath/q=query)"),
    ("$1:5052/subpath/q=query#anchor",
     "ok(http://$1:5052/subpath/q=query#anchor)"),
    ("$1:5052/subpath",
     "ok(http://$1:5052/subpath)"),
    ("$1:5052/subpath?q=query",
     "ok(http://$1:5052/subpath?q=query)"),
    ("$1:5052/subpath?q=query#anchor",
     "ok(http://$1:5052/subpath?q=query#anchor)"),

    ("bnode://$1:5052",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052?q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052?q=query#anchor",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/q=query#anchor",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath?q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath?q=query#anchor",
     "err(Unknown scheme value)"),

    ("//$1:5052",
     "ok(http://$1:5052)"),
    ("//$1:5052?q=query",
     "ok(http://$1:5052?q=query)"),
    ("//$1:5052?q=query#anchor",
     "ok(http://$1:5052?q=query#anchor)"),
    ("//$1:5052/subpath/",
     "ok(http://$1:5052/subpath/)"),
    ("//$1:5052/subpath/q=query",
     "ok(http://$1:5052/subpath/q=query)"),
    ("//$1:5052/subpath/q=query#anchor",
     "ok(http://$1:5052/subpath/q=query#anchor)"),
    ("//$1:5052/subpath",
     "ok(http://$1:5052/subpath)"),
    ("//$1:5052/subpath?q=query",
     "ok(http://$1:5052/subpath?q=query)"),
    ("//$1:5052/subpath?q=query#anchor",
     "ok(http://$1:5052/subpath?q=query#anchor)"),

    ("//$1", "err(Missing port number)"),
    ("//$1?q=query", "err(Missing port number)"),
    ("//$1?q=query#anchor", "err(Missing port number)"),
    ("//$1/subpath/", "err(Missing port number)"),
    ("//$1/subpath/q=query", "err(Missing port number)"),
    ("//$1/subpath/q=query#anchor", "err(Missing port number)"),
    ("//$1/subpath", "err(Missing port number)"),
    ("//$1/subpath?q=query", "err(Missing port number)"),
    ("//$1/subpath?q=query#anchor", "err(Missing port number)"),

    ("$1", "err(Missing port number)"),
    ("$1?q=query", "err(Missing port number)"),
    ("$1?q=query#anchor", "err(Missing port number)"),
    ("$1/subpath/", "err(Missing port number)"),
    ("$1/subpath/q=query", "err(Missing port number)"),
    ("$1/subpath/q=query#anchor", "err(Missing port number)"),
    ("$1/subpath", "err(Missing port number)"),
    ("$1/subpath?q=query", "err(Missing port number)"),
    ("$1/subpath?q=query#anchor", "err(Missing port number)"),

    ("", "err(Missing hostname)")
  ]

suite "Validator Client test suite":
  test "normalizeUri() test vectors":
    for hostname in HostNames:
      for vector in GoodTestVectors:
        let expect = vector[1] % (hostname)
        check $normalizeUri(parseUri(vector[0] % (hostname))) == expect
