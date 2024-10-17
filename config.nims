import std/strutils

--noNimblePath

const currentDir = currentSourcePath()[0 .. ^(len("config.nims") + 1)]

if getEnv("NIMBUS_BUILD_SYSTEM") == "yes" and
   system.fileExists(currentDir & "nimbus-build-system.paths"):
  include "nimbus-build-system.paths"

const nimCachePathOverride {.strdefine.} = ""
when nimCachePathOverride == "":
  when defined(release):
    let nimCachePath = "nimcache/release/" & projectName()
  else:
    let nimCachePath = "nimcache/debug/" & projectName()
else:
  let nimCachePath = nimCachePathOverride
switch("nimcache", nimCachePath)

switch("passC", "-fsanitize=undefined")
switch("passL", "-fsanitize=undefined")

switch("passC", "-fno-omit-frame-pointer")
switch("passL", "-fno-omit-frame-pointer")

--mm:refc

switch("define", "nim_compiler_path=" & currentDir & "env.sh nim")
switch("define", "withoutPCRE")

--define:kzgExternalBlst

put("secp256k1.always", "-fno-lto -fomit-frame-pointer")
