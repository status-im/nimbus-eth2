{.used.}

import
  unittest, stint, blscurve, ./testutil, stew/byteutils,
  ../beacon_chain/[extras, interop, ssz],
  ../beacon_chain/spec/[beaconstate, crypto, helpers, datatypes]

# Interop test yaml, found here:
# https://github.com/ethereum/eth2.0-pm/blob/a0b9d22fad424574b1307828f867b30237758468/interop/mocked_start/keygen_10_validators.yaml

const privateKeys = [
  "0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866",
  "0x51d0b65185db6989ab0b560d6deed19c7ead0e24b9b6372cbecb1f26bdfad000",
  "0x315ed405fafe339603932eebe8dbfd650ce5dafa561f6928664c75db85f97857",
  "0x25b1166a43c109cb330af8945d364722757c65ed2bfed5444b5a2f057f82d391",
  "0x3f5615898238c4c4f906b507ee917e9ea1bb69b93f1dbd11a34d229c3b06784b",
  "0x055794614bc85ed5436c1f5cab586aab6ca84835788621091f4f3b813761e7a8",
  "0x1023c68852075965e0f7352dee3f76a84a83e7582c181c10179936c6d6348893",
  "0x3a941600dc41e5d20e818473b817a28507c23cdfdb4b659c15461ee5c71e41f5",
  "0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06",
  "0x2b3b88a041168a1c4cd04bdd8de7964fd35238f95442dc678514f9dadb81ec34",
]

type DepositConfig = object
  privkey: ValidatorPrivKey
  signing_root: array[32, byte]
  domain: DomainType
  sig: ValidatorSig

# Generated from
#   - https://github.com/status-im/eth2.0-specs/blob/c58096754b62389b0ea75dbdd717d362691b7c34/test_libs/pyspec/mockup_genesis.py
#   - "zcli genesis mock" https://github.com/protolambda/zcli

let depositsConfig = [
  DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x25295f0d1d592a90b333e26e85149708208e9f8e8bc18f6c77bd62f8ad7a6866"),
    signing_root: hexToByteArray[32]("139b510ea7f2788ab82da1f427d6cbe1db147c15a053db738ad5500cd83754a6"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"8684b7f46d25cdd6f937acdaa54bdd2fb34c78d687dca93884ba79e60ebb0df964faa4c49f3469fb882a50c7726985ff0b20c9584cc1ded7c90467422674a05177b2019661f78a5c5c56f67d586f04fd37f555b4876a910bedff830c2bece0aa"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x51d0b65185db6989ab0b560d6deed19c7ead0e24b9b6372cbecb1f26bdfad000"),
    signing_root: hexToByteArray[32]("bb4b6184b25873cdf430df3838c8d3e3d16cf3dc3b214e2f3ab7df9e6d5a9b52"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"a2c86c4f654a2a229a287aabc8c63f224d9fb8e1d77d4a13276a87a80c8b75aa7c55826febe4bae6c826aeeccaa82f370517db4f0d5eed5fbc06a3846088871696b3c32ff3fdebdb52355d1eede85bcd71aaa2c00d6cf088a647332edc21e4f3"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x315ed405fafe339603932eebe8dbfd650ce5dafa561f6928664c75db85f97857"),
    signing_root: hexToByteArray[32]("c6ddd74b1b45db17a864c87dd941cb6c6e16540c534cdbe1cc0d43e9a5d87f7c"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"a5a463d036e9ccb19757b2ddb1e6564a00463aed1ef51bf69264a14b6bfcff93eb6f63664e0df0b5c9e6760c560cb58d135265cecbf360a23641af627bcb17cf6c0541768d3f3b61e27f7c44f21b02cd09b52443405b12fb541f5762cd615d6e"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x25b1166a43c109cb330af8945d364722757c65ed2bfed5444b5a2f057f82d391"),
    signing_root: hexToByteArray[32]("9397cd33d4e8883dbdc1a1d7df410aa2b627740d11c5574697a2d483a50ab7bb"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"8731c258353c8aa46a8e38509eecfdc32018429239d9acad9b634a4d010ca51395828c0c056808c6e6df373fef7e9a570b3d648ec455d90f497e12fc3011148eded7265b0f995de72e5982db1dbb6eca8275fc99cdd10704b8cf19ec0bb9c350"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x3f5615898238c4c4f906b507ee917e9ea1bb69b93f1dbd11a34d229c3b06784b"),
    signing_root: hexToByteArray[32]("27340cc0f3b76bcc89c78e67166c13a58c97c232889391d1387fc404c4f5255e"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"90b20f054f6a2823d66e159050915335e7a4f64bf7ac449ef83bb1d1ba9a6b2385da977b5ba295ea2d019ee3a8140607079d671352ab233b3bf6be45c61dce5b443f23716d64382e34d7676ae64eedd01babeeb8bfd26386371f6bc01f1d4539"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x055794614bc85ed5436c1f5cab586aab6ca84835788621091f4f3b813761e7a8"),
    signing_root: hexToByteArray[32]("b8cf48542d8531ae59b56e175228e7fcb82415649b5e992e132d3234b31dda2f"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"99df72b850141c67fc956a5ba91abb5a091538d963aa6c082e1ea30b7f7e5a54ec0ff79c749342d4635e4901e8dfc9b90604d5466ff2a7b028c53d4dac01ffb3ac0555abd3f52d35aa1ece7e8e9cce273416b3cf582a5f2190e87a3b15641f0c"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x1023c68852075965e0f7352dee3f76a84a83e7582c181c10179936c6d6348893"),
    signing_root: hexToByteArray[32]("5f919d91faecece67422edf573a507fc5f9720f4e37063cceb40aa3b371f1aa9"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"a4023f36f4f354f69b615b3651596d4b479f005b04f80ef878aaeb342e94ad6f9acddf237309a79247d560b05f4f7139048b5eee0f08da3a11f3ee148ca76e3e1351a733250515a61e12027468cff2de193ab8ee5cd90bdd1c50e529edda512b"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x3a941600dc41e5d20e818473b817a28507c23cdfdb4b659c15461ee5c71e41f5"),
    signing_root: hexToByteArray[32]("d2ff8bfda7e7bcc64c636a4855d2a1eccb7f47379f526a753fd934ae37ba9ec7"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"81c52ada6d975a5b968509ab16fa58d617dd36a6c333e6ed86a7977030e4c5d37a488596c6776c2cdf4831ea7337ad7902020092f60e547714449253a947277681ff80b7bf641ca782214fc9ec9b58c66ab43c0a554c133073c96ad35edff101"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x066e3bdc0415530e5c7fed6382d5c822c192b620203cf669903e1810a8c67d06"),
    signing_root: hexToByteArray[32]("1e19687d32785632ddc9b6b319690ea45c0ea20d7bc8aacbd33f6ebbe30816e1"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"b4aab8f6624f61f4f5eb6d75839919a3ef6b4e1b19cae6ef063d6281b60ff1d5efe02bcbfc4b9eb1038c42e0a3325d8a0fcf7b64ff3cd9df5c629b864dfdc5b763283254ccd6cfa28cff53e477fb1743440a18d76a776ec4d66c5f50d695ca85"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x2b3b88a041168a1c4cd04bdd8de7964fd35238f95442dc678514f9dadb81ec34"),
    signing_root: hexToByteArray[32]("64a910a0a3e7da9a7a29ee2c92859314a160040ffb2042641fc56cba75b78012"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"9603f7dcab6822edb92eb588f1e15fcc685ceb8bcc7257adb0e4a5995820b8ef77215650792120aff871f30a52475ea31212aa741a3f0e6b2dbcb3a63181571306a411c772a7fd08826ddeab98d1c47b5ead82f8e063b9d7f1f217808ee4fb50"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x2e62dbea7fe3127c3b236a92795dd633be51ee7cdfe5424882a2f355df497117"),
    signing_root: hexToByteArray[32]("5bf0c7a39df536b3c8a5dc550f0163af0b33a56b9454b5240cea9ad8356c4117"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"92b04a4128e84b827b46fd91611acc46f97826d13fbdcbf000b6b3585edd8629e38d4c13f7f3fde5a1170f4f3f55bef21883498602396c875275cb2c795d4488383b1e931fefe813296beea823c228af9e0d97e65742d380a0bbd6f370a89b23"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x2042dc809c130e91906c9cb0be2fec0d6afaa8f22635efc7a3c2dbf833c1851a"),
    signing_root: hexToByteArray[32]("e8a45fa71addd854d8d78e0b2cdc8f9100c8a5e03d894c1c382068e8aa4b71e2"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"89ac6297195e768b5e88cbbb047d8b81c77550c9462df5750f4b899fc0de985fa9e16fccc6c6bd71124eb7806064b7110d534fb8f6ccaf118074cd4f4fac8a22442e8facc2cd380ddc4ebf6b9c2f7e956f418279dc04a6737ede6d7763396ed9"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x15283c540041cd85c4533ee47517c8bb101c6207e9acbba2935287405a78502c"),
    signing_root: hexToByteArray[32]("3dfab0daa3be9c72c5dd3b383e756d6048bb76cd3d09abb4dc991211ae8a547b"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"8adee09a19ca26d5753b9aa447b0af188a769f061d11bf40b32937ad3fa142ca9bc164323631a4bb78f0a5d4fd1262010134adc723ab377a2e6e362d3e2130a46b0a2088517aee519a424147f043cc5007a13f2d2d5311c18ee2f694ca3f19fc"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x03c85e538e1bb30235a87a3758c5571753ca1308b7dee321b74c19f78423999b"),
    signing_root: hexToByteArray[32]("8905ae60c419e38f263eb818a5536e4144df3c0a800132e07594d457c62b5825"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"90dc90a295644da5c6d441cd0b33e34b8f1f77230755fd78b9ecbd86fd6e845e554c0579ab88c76ca14b56d9f0749f310cd884c193ec69623ccd724469268574c985ee614e80f00331c24f78a3638576d304c67c2aa6ce8949652257581c18a5"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x45a577d5cab31ac5cfff381500e09655f0799f29b130e6ad61c1eec4b15bf8dd"),
    signing_root: hexToByteArray[32]("702d1bd9c27c999923149f6c6578c835943b58b90845086bbf5be3b94aa4663d"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"9338c8b0050cdb464efae738d6d89ac48d5839ce750e3f1f20acd52a0b61e5c033fa186d3ed0ddf5856af6c4815971b00a68002b1eba45f5af27f91cad04831e32157fecf5fb091a8087829e2d3dd3438e0b86ff8d036be4a3876fa0dfa60e6c"
  ), DepositConfig(
    privkey: ValidatorPrivKey.init(hexToSeqByte"0x03cffafa1cbaa7e585eaee07a9d35ae57f6dfe19a9ea53af9c37e9f3dfac617c"),
    signing_root: hexToByteArray[32]("77f3da02c410e9ccba39d89983c52e6e77ca5dec3ae423311a578ee28b2ec0cd"),
    domain: DOMAIN_DEPOSIT,
    sig: ValidatorSig.fromHex"8819f719f7af378f27fe65c699b5206f1f7bbfd62200cab09e7ffe3d8fce0346eaa84b274d66d700cd1a0c0c7b46f62100afb2601270292ddf6a2bddff0248bb8ed6085d10c8c9e691a24b15d74bc7a9fcf931d953300d133f8c0e772704b9ba"
  )
]

suite "Interop":
  timedTest "Mocked start private key":
    for i, k in privateKeys:
      let
        key = makeInteropPrivKey(i)
        v = k.parse(UInt256, 16)

      check:
        # getBytes is bigendian and returns full 48 bytes of key..
        Uint256.fromBytesBE(key.getBytes()[48-32..<48]) == v

  timedTest "Interop signatures":
    for dep in depositsConfig:
      let computed_sig = bls_sign(
        key = dep.privkey,
        msg = dep.signing_root,
        domain = compute_domain(dep.domain)
      )

      check:
        dep.sig == computed_sig

  timedTest "Interop genesis":
    # Check against https://github.com/protolambda/zcli:
    # zcli keys generate --to 64 | zcli genesis mock --genesis-time 1570500000 > /tmp/state.ssz
    # zcli hash-tree-root state /tmp/state.ssz
    var deposits: seq[Deposit]

    for i in 0..<64:
      let
        privKey = makeInteropPrivKey(i)
      deposits.add(makeDeposit(privKey.pubKey(), privKey))

    var
      initialState = initialize_beacon_state_from_eth1(
        eth1BlockHash, 1570500000, deposits, {skipMerkleValidation})

    # https://github.com/ethereum/eth2.0-pm/tree/6e41fcf383ebeb5125938850d8e9b4e9888389b4/interop/mocked_start#create-genesis-state
    initialState.genesis_time = 1570500000

    let expected =
      when const_preset == "minimal":
        "5a3bbcae4ab2b4eafded947689fd7bd8214a616ffffd2521befdfe2a3b2f74c0"
      elif const_preset == "mainnet":
        "db0a887acd5e201ac579d6cdc0c4932f2a0adf342d84dc5cd11ce959fbce3760"
      else:
        "unimplemented"
    check:
      hash_tree_root(initialState).data.toHex() == expected
