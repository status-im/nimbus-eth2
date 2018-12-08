import os, ospaths, milagro_crypto, nimcrypto, ./spec/digest

proc writeFile(filename: string, content: openarray[byte]) =
  var s = newString(content.len)
  if content.len != 0:
    copyMem(addr s[0], unsafeAddr content[0], content.len)
  writeFile(filename, s)

proc genKeys(path: string) =
  let pk = newSigKey()
  var randaoSeed: Eth2Digest
  if randomBytes(randaoSeed.data) != sizeof(randaoSeed.data):
    raise newException(Exception, "Could not generate randao seed")

  createDir(parentDir(path))
  let pkPath = path & ".privkey"
  let randaoPath = path & ".randao"
  writeFile(randaoPath, randaoSeed.data)
  writeFile(pkPath, pk.getRaw())
  echo "Generated privkey: ", pkPath
  echo "Generated randao seed: ", randaoPath

proc printUsage() =
  echo "Usage: validator_keygen <path>"

proc main() =
  if paramCount() != 1:
    printUsage()
    return

  let path = paramStr(1)
  genKeys(path)


when isMainModule:
  main()

