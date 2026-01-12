# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/engine_authentication

suite "engine API authentication":
  test "getIatToken":
    check:
      $getIatToken(0)          == "{\"iat\":0}"
      $getIatToken(1)          == "{\"iat\":1}"
      $getIatToken(2)          == "{\"iat\":2}"
      $getIatToken(14)         == "{\"iat\":14}"
      $getIatToken(60)         == "{\"iat\":60}"
      $getIatToken(95)         == "{\"iat\":95}"
      $getIatToken(487)        == "{\"iat\":487}"
      $getIatToken(529)        == "{\"iat\":529}"
      $getIatToken(666)        == "{\"iat\":666}"
      $getIatToken(2669)       == "{\"iat\":2669}"
      $getIatToken(6082)       == "{\"iat\":6082}"
      $getIatToken(6234)       == "{\"iat\":6234}"
      $getIatToken(230158)     == "{\"iat\":230158}"
      $getIatToken(675817)     == "{\"iat\":675817}"
      $getIatToken(695159)     == "{\"iat\":695159}"
      $getIatToken(19257188)   == "{\"iat\":19257188}"
      $getIatToken(52639657)   == "{\"iat\":52639657}"
      $getIatToken(71947005)   == "{\"iat\":71947005}"
      $getIatToken(1169144470) == "{\"iat\":1169144470}"
      $getIatToken(2931679730) == "{\"iat\":2931679730}"
      $getIatToken(3339327695) == "{\"iat\":3339327695}"

  test "HS256 JWS signing":
    let secret = parseJwtSharedKey("0x16bb0c58f546a90d2fcfe295f50dd4e60aaa48ecd5d61a4569765d1b77784d34").expect("valid key")
    check:
      # https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-hs256
      getSignedToken(secret, "{\"some\":\"payload\"}") == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Ku0XnrSVRMgWutypu6KXgLiiMFJc_viVGJRhbxRP_AU"

  test "HS256 JWS iat token signing":
    let secret = parseJwtSharedKey("0x16bb0c58f546a90d2fcfe295f50dd4e60aaa48ecd5d61a4569765d1b77784d34").expect("valid key")
    # https://pyjwt.readthedocs.io/en/stable/usage.html
      # sort_keys=False ensures that the header is encoded in the same order as we use
    # >>> secret = bytes.fromhex("16bb0c58f546a90d2fcfe295f50dd4e60aaa48ecd5d61a4569765d1b77784d34")
    # >>> for i in [0, 1, 2, 14, 60, 95, 487, 529, 2669, 6082, 6234, 230158, 675817, 695159, 19257188, 52639657, 71947005, 1169144470, 2931679730, 3339327695]:
    #...   print('      getSignedIatToken(secret, %d) == "%s"'%(i, jwt.encode({"iat": i}, secret, algorithm="HS256", sort_keys=False)))
    check:
      getSignedIatToken(secret, 0) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjB9.QGNQ2NmP9yWCTc1myLyj5xBgNX7GvJsZOMRS0ope_Qw"
      getSignedIatToken(secret, 1) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjF9.nwzloKy77j4wyEeq05b7sCIILNrwOymg1M9dtvJvD20"
      getSignedIatToken(secret, 2) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjJ9.Tm-rxRRO2ycmteuSkiciE-KScKCiyqnjaQXuMauPKtE"
      getSignedIatToken(secret, 14) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0fQ.wDcw2rZsiT2AP2LMXE-8vEz7aoztVUM4b6wDbuE1UU8"
      getSignedIatToken(secret, 60) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjYwfQ.K8OKg3ZxujDiULWlkierZILEhvHiNyr9zAQzo6_xmRo"
      getSignedIatToken(secret, 95) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjk1fQ.yhZWklNsK3JYvzMB867MD89y-czjXfXVdqNZ4G8fKKA"
      getSignedIatToken(secret, 487) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjQ4N30.e0D__OXkjno8Hm35vW1DY19CStV4_PEVfkrA8JzvTws"
      getSignedIatToken(secret, 529) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjUyOX0.6howC0fIcvcGRHbaU-U-AXhwnokXIdQA4lRGmiW5OWc"
      getSignedIatToken(secret, 2669) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjI2Njl9.2qs8jX7nWwqrgi6v4zEeRGGHvRACp3BBzDMP5IHP8G0"
      getSignedIatToken(secret, 6082) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjYwODJ9.XLWfpPZSS91setVUWPgiQhfkNH67mMZXu6_MxvugQ0A"
      getSignedIatToken(secret, 6234) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjYyMzR9.a19HeRfVbGmDVQqAJIlNWiOoNJ9o51QT_01fZq6JA_M"
      getSignedIatToken(secret, 230158) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjIzMDE1OH0.aQDRym5vA0jZ1nbfD01jqx7XxGPlZxhvmxLhvuWRf4E"
      getSignedIatToken(secret, 675817) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjY3NTgxN30.IOXXc58UmxVsL9am113vmJ7EHwavVYYllrruQMJoMSc"
      getSignedIatToken(secret, 695159) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjY5NTE1OX0.uzUWhm9_sl0TZI0LN57Ay8MW8loY8EwM1oNPzCPOio0"
      getSignedIatToken(secret, 19257188) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE5MjU3MTg4fQ.D42LqNic0gsmarnL0l1XP5ylBwMqYT7pGr_6wZhvcPM"
      getSignedIatToken(secret, 52639657) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjUyNjM5NjU3fQ.Xg4Ipcs3xu4O8McyDswIld7ROZM73DY73ryc1vWGMZI"
      getSignedIatToken(secret, 71947005) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjcxOTQ3MDA1fQ.4C10E4Il-cmNAmU2sGKkAQfgoSJO4ReTvGiCzo0KzYU"
      getSignedIatToken(secret, 1169144470) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjExNjkxNDQ0NzB9.eYSTnh6mqN_0wVyqj1biL9QwLGxr1l51IDMHTKizqmo"
      getSignedIatToken(secret, 2931679730) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjI5MzE2Nzk3MzB9.Mljj-2-BhxFXkkROuvU7_DMtoVROiE-iOMnPR5uyZA0"
      getSignedIatToken(secret, 3339327695) == "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjMzMzkzMjc2OTV9.C_9IaA1RM6jMKhUqr8S7rvFD2OkYOT2xjx_DR4CPFX4"
