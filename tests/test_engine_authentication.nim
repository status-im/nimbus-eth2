# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import std/[json, sequtils], unittest2, ../beacon_chain/spec/engine_authentication

suite "engine API authentication":
  test "getIatToken":
    check:
      $getIatToken(0) == "{\"iat\":0}"
      $getIatToken(1) == "{\"iat\":1}"
      $getIatToken(2) == "{\"iat\":2}"
      $getIatToken(14) == "{\"iat\":14}"
      $getIatToken(60) == "{\"iat\":60}"
      $getIatToken(95) == "{\"iat\":95}"
      $getIatToken(487) == "{\"iat\":487}"
      $getIatToken(529) == "{\"iat\":529}"
      $getIatToken(666) == "{\"iat\":666}"
      $getIatToken(2669) == "{\"iat\":2669}"
      $getIatToken(6082) == "{\"iat\":6082}"
      $getIatToken(6234) == "{\"iat\":6234}"
      $getIatToken(230158) == "{\"iat\":230158}"
      $getIatToken(675817) == "{\"iat\":675817}"
      $getIatToken(695159) == "{\"iat\":695159}"
      $getIatToken(19257188) == "{\"iat\":19257188}"
      $getIatToken(52639657) == "{\"iat\":52639657}"
      $getIatToken(71947005) == "{\"iat\":71947005}"
      $getIatToken(1169144470) == "{\"iat\":1169144470}"
      $getIatToken(2931679730) == "{\"iat\":2931679730}"
      $getIatToken(3339327695) == "{\"iat\":3339327695}"

  test "HS256 JWS signing":
    let secret = mapIt("secret", byte(it))
    check:
      # https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-hs256
      # The pyjwt version I have swaps the order of the fields in the header, so creates this
      # different result from their website. Both are valid, and RFC 7515 has another example
      # of a slightly different ordering/whitespace combination. It just has to decode as the
      # same JSON, semantically.
      getSignedToken(secret, "{\"some\":\"payload\"}") ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U"

  test "HS256 JWS iat token signing":
    let secret = mapIt("secret", byte(it))
    # https://pyjwt.readthedocs.io/en/stable/usage.html
    # >>> for i in [0, 1, 2, 14, 60, 95, 487, 529, 2669, 6082, 6234, 230158, 675817, 695159, 19257188, 52639657, 71947005, 1169144470, 29316
    #...   print('      getSignedIatToken(secret, %d) == "%s"'%(i, jwt.encode({"iat": i}, "secret", algorithm="HS256")))
    check:
      getSignedIatToken(secret, 0) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjB9.BA9VRUphKugikQmUzIL-6kyi9Wa1IWeli25hY8n5w7M"
      getSignedIatToken(secret, 1) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjF9.SjP9sSFaSm1pgnnVtx-M7Bq06xoenJUJldFRn1HpB5g"
      getSignedIatToken(secret, 2) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjJ9.VA2Qo_m1MtT_DXiNt06UFcFTxEd90GjggsJC1H2XL2U"
      getSignedIatToken(secret, 14) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE0fQ.I7YMwh9o23qr5iK6YSgflG3nCCtzJFoSSMDTXSMJoZ4"
      getSignedIatToken(secret, 60) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjYwfQ.3-5HWzbM9ICMADiXshOKdBVP2RsWKdpcaw1uK_x0B-w"
      getSignedIatToken(secret, 95) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjk1fQ.mERclea8y-SjN6qAZFWoXKydrLTgnzHNgvJ87zbYc8k"
      getSignedIatToken(secret, 487) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjQ4N30.Z6xuP1n4vUOqKgMdCQrDREOoBVSfvUlXcNzw5B-BA8k"
      getSignedIatToken(secret, 529) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjUyOX0.VSWpcLQEp_fdGZGjAHvYFYAyfc8Pzt3V-hRZUngMf8Y"
      getSignedIatToken(secret, 2669) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjI2Njl9.jeBC5FfU6amVKGmCqZxUHSqumd8AYEa-mnk0V_QNBn4"
      getSignedIatToken(secret, 6082) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjYwODJ9.Ua9q9HTc1jv8S5_Lpg0w-mFV293rrrtXnS7jUhH8pxE"
      getSignedIatToken(secret, 6234) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjYyMzR9.8nSB6zb4zrAcH1vW5OcOt1ru1RkuLRTFLVv1VQW8BS0"
      getSignedIatToken(secret, 230158) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjIzMDE1OH0.IwjEyz0__xlp1bMitC5YmEIR0emGgqin7Bknm9pDrYM"
      getSignedIatToken(secret, 675817) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjY3NTgxN30.mKhib1fJ0KQy8X8T0xPN89DZootODNlBXOIksdVnmf4"
      getSignedIatToken(secret, 695159) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjY5NTE1OX0.KJClqQMaEVnFksdScc_SprEWqpxDtFUrXxZCsALqkpk"
      getSignedIatToken(secret, 19257188) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE5MjU3MTg4fQ.Q_BssigyQGRDkV9ysGcGKIzEEXMpVpv0t4Bx4pf7lr4"
      getSignedIatToken(secret, 52639657) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjUyNjM5NjU3fQ.O0cI2U_kEW1MbWyXcAh146mRU2CwzMNegAQit_1-TNU"
      getSignedIatToken(secret, 71947005) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjcxOTQ3MDA1fQ.pQwPWxMHzWGvTTfRfWKiGX8qEI2NcZbnB3ruh4Wcftg"
      getSignedIatToken(secret, 1169144470) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjExNjkxNDQ0NzB9.5JS0pVVh1g8hxO_PDQpwCvFnh1tdRtodpALXU1xol4I"
      getSignedIatToken(secret, 2931679730) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjI5MzE2Nzk3MzB9.0ZR8DiVy6Y_pOleGC9Ti3M8ShtH5hyCBhceO1C2OTj0"
      getSignedIatToken(secret, 3339327695) ==
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjMzMzkzMjc2OTV9.ZRYaNrsvcIzppVeNorYUgEmVXcwOOQbqPlCQcoAaO4k"
