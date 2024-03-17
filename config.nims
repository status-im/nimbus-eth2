import std/strutils

--noNimblePath

const currentDir = currentSourcePath()[0 .. ^(len("config.nims") + 1)]

if getEnv("NIMBUS_BUILD_SYSTEM") == "yes" and
   # BEWARE
   # In Nim 1.6, config files are evaluated with a working directory
   # matching where the Nim command was invocated. This means that we
   # must do all file existance checks with full absolute paths:
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

# `-flto` gives a significant improvement in processing speed, specially hash tree and state transition (basically any CPU-bound code implemented in nim)
# With LTO enabled, optimization flags should be passed to both compiler and linker!
if defined(release) and not defined(disableLTO):
  # "-w" is not passed to the compiler during linking, so we need to disable
  # some warnings by hand.
  switch("passL", "-Wno-stringop-overflow -Wno-stringop-overread")

  if defined(macosx): # Clang
    switch("passC", "-flto=thin")
    switch("passL", "-flto=thin -Wl,-object_path_lto," & nimCachePath & "/lto")
  elif defined(linux):
    switch("passC", "-flto=auto")
    switch("passL", "-flto=auto")
    switch("passC", "-finline-limit=100000")
    switch("passL", "-finline-limit=100000")

# Hidden visibility allows for better position-independent codegen - it also
# resolves a build issue in BLST where otherwise private symbols would require
# an unsupported relocation on PIE-enabled distros such as ubuntu - BLST itself
# solves this via a linker script which is messy
switch("passC", "-fvisibility=hidden")

# omitting frame pointers in nim breaks the GC
# https://github.com/nim-lang/Nim/issues/10625
switch("passC", "-fno-omit-frame-pointer")
switch("passL", "-fno-omit-frame-pointer")

--threads:on
--opt:speed
--mm:refc
--define:chronicles_line_numbers # These are disabled for release binaries

switch("define", "nim_compiler_path=" & currentDir & "env.sh nim")
switch("define", "withoutPCRE")

when true:
  --define:nimStackTraceOverride
  switch("import", "libbacktrace")

var canEnableDebuggingSymbols = true
if defined(macosx):
  # The default open files limit is too low on macOS (512), breaking the
  # "--debugger:native" build. It can be increased with `ulimit -n 1024`.
  let openFilesLimitTarget = 1024
  var openFilesLimit = 0
  try:
    openFilesLimit = staticExec("ulimit -n").strip(chars = Whitespace + Newlines).parseInt()
    if openFilesLimit < openFilesLimitTarget:
      echo "Open files limit too low to enable debugging symbols and lightweight stack traces."
      echo "Increase it with \"ulimit -n " & $openFilesLimitTarget & "\""
      canEnableDebuggingSymbols = false
  except:
    echo "ulimit error"
# We ignore this resource limit on Windows, where a default `ulimit -n` of 256
# in Git Bash is apparently ignored by the OS, and on Linux where the default of
# 1024 is good enough for us.

if canEnableDebuggingSymbols:
  # add debugging symbols and original files and line numbers
  --debugger:native

--define:nimOldCaseObjects # https://github.com/status-im/nim-confutils/issues/9

# `switch("warning[CaseTransition]", "off")` fails with "Error: invalid command line option: '--warning[CaseTransition]'"
switch("warning", "CaseTransition:off")

# The compiler doth protest too much, methinks, about all these cases where it can't
# do its (N)RVO pass: https://github.com/nim-lang/RFCs/issues/230
switch("warning", "ObservableStores:off")

# Too many false positives for "Warning: method has lock level <unknown>, but another method has 0 [LockLevel]"
switch("warning", "LockLevel:off")

# Too many right now to read compiler output. Warnings are legitimate, but
# should be fixed out-of-band of `unstable` branch.
switch("warning", "BareExcept:off")

--define:kzgExternalBlst

# ############################################################
#
#                    No LTO for crypto
#
# ############################################################

# This applies per-file compiler flags to C files
# which do not support {.localPassC: "-fno-lto".}
# Unfortunately this is filename based instead of path-based
# Assumes GCC

# BLST
put("server.always", "-fno-lto")
put("assembly.always", "-fno-lto")

# Secp256k1
put("secp256k1.always", "-fno-lto")

# BearSSL - only RNGs
put("aesctr_drbg.always", "-fno-lto")
put("hmac_drbg.always", "-fno-lto")
put("sysrng.always", "-fno-lto")

# ############################################################
#
#                    Spurious warnings
#
# ############################################################

# sqlite3.c: In function ‘sqlite3SelectNew’:
# vendor/nim-sqlite3-abi/sqlite3.c:124500: warning: function may return address of local variable [-Wreturn-local-addr]
put("sqlite3.always", "-fno-lto") # -Wno-return-local-addr
