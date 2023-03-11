import strutils

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
  else:
    # On windows, LTO needs more love and attention so "gcc-ar" and "gcc-ranlib" are
    # used for static libraries.
    discard

# show C compiler warnings
if defined(cwarnings):
  let common_gcc_options = "-Wno-discarded-qualifiers -Wno-incompatible-pointer-types"
  if defined(windows):
    put("gcc.options.always", "-mno-ms-bitfields " & common_gcc_options)
    put("clang.options.always", "-mno-ms-bitfields " & common_gcc_options)
  else:
    put("gcc.options.always", common_gcc_options)
    put("clang.options.always", common_gcc_options)

if defined(limitStackUsage):
  # This limits stack usage of each individual function to 1MB - the option is
  # available on some GCC versions but not all - run with `-d:limitStackUsage`
  # and look for .su files in "./build/", "./nimcache/" or $TMPDIR that list the
  # stack size of each function.
  switch("passC", "-fstack-usage -Werror=stack-usage=1048576")
  switch("passL", "-fstack-usage -Werror=stack-usage=1048576")

if defined(windows):
  # disable timestamps in Windows PE headers - https://wiki.debian.org/ReproducibleBuilds/TimestampsInPEBinaries
  switch("passL", "-Wl,--no-insert-timestamp")
  # increase stack size
  switch("passL", "-Wl,--stack,8388608")
  # https://github.com/nim-lang/Nim/issues/4057
  --tlsEmulation:off
  if defined(i386):
    # set the IMAGE_FILE_LARGE_ADDRESS_AWARE flag so we can use PAE, if enabled, and access more than 2 GiB of RAM
    switch("passL", "-Wl,--large-address-aware")

  # The dynamic Chronicles output currently prevents us from using colors on Windows
  # because these require direct manipulations of the stdout File object.
  switch("define", "chronicles_colors=off")

  # Avoid some rare stack corruption while using exceptions with a SEH-enabled
  # toolchain: https://github.com/status-im/nimbus-eth2/issues/3121
  switch("define", "nimRawSetjmp")

# This helps especially for 32-bit x86, which sans SSE2 and newer instructions
# requires quite roundabout code generation for cryptography, and other 64-bit
# and larger arithmetic use cases, along with register starvation issues. When
# engineering a more portable binary release, this should be tweaked but still
# use at least -msse2 or -msse3.
#
# https://github.com/status-im/nimbus-eth2/blob/stable/docs/cpu_features.md#ssse3-supplemental-sse3
# suggests that SHA256 hashing with SSSE3 is 20% faster than without SSSE3, so
# given its near-ubiquity in the x86 installed base, it renders a distribution
# build more viable on an overall broader range of hardware.
#
if defined(disableMarchNative):
  if defined(i386) or defined(amd64):
    if defined(macosx):
      # https://support.apple.com/kb/sp803
      # "macOS Catalina - Technical Specifications": EOL as of 2022-09
      # https://support.apple.com/kb/sp833
      # "macOS Big Sur - Technical Specifications" lists current oldest
      # supported models: MacBook (2015 or later), MacBook Air (2013 or later),
      # MacBook Pro (Late 2013 or later), Mac mini (2014 or later), iMac (2014
      # or later), iMac Pro (2017 or later), Mac Pro (2013 or later).
      #
      # These all have Haswell or newer CPUs.
      #
      # This ensures AVX2, AES-NI, PCLMUL, BMI1, and BMI2 instruction set support.
      switch("passC", "-march=haswell -mtune=generic")
      switch("passL", "-march=haswell -mtune=generic")
    else:
      switch("passC", "-mssse3")
      switch("passL", "-mssse3")
elif defined(macosx) and defined(arm64):
  # Apple's Clang can't handle "-march=native" on M1: https://github.com/status-im/nimbus-eth2/issues/2758
  switch("passC", "-mcpu=apple-m1")
  switch("passL", "-mcpu=apple-m1")
else:
  switch("passC", "-march=native")
  switch("passL", "-march=native")
  if defined(windows):
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65782
    # ("-fno-asynchronous-unwind-tables" breaks Nim's exception raising, sometimes)
    switch("passC", "-mno-avx512f")
    switch("passL", "-mno-avx512f")

# omitting frame pointers in nim breaks the GC
# https://github.com/nim-lang/Nim/issues/10625
switch("passC", "-fno-omit-frame-pointer")
switch("passL", "-fno-omit-frame-pointer")

--threads:on
--opt:speed
--excessiveStackTrace:on
# enable metric collection
--define:metrics
--define:chronicles_line_numbers # These are disabled for release binaries
# for heap-usage-by-instance-type metrics and object base-type strings
--define:nimTypeNames

switch("define", "nim_compiler_path=" & currentDir & "env.sh nim")
switch("define", "withoutPCRE")

switch("import", "testutils/moduletests")

when not defined(disable_libbacktrace):
  --define:nimStackTraceOverride
  switch("import", "libbacktrace")
else:
  --stacktrace:on
  --linetrace:on

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
if (NimMajor, NimMinor, NimPatch) >= (1, 6, 11):
  switch("warning", "BareExcept:off")

# Too many of these because of Defect compat in 1.2
switch("hint", "XCannotRaiseY:off")

# Useful for Chronos metrics.
#--define:chronosFutureTracking

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

# Miracl - only ECP to derive public key from private key
put("ecp_BLS12381.always", "-fno-lto")

# ############################################################
#
#                    Spurious warnings
#
# ############################################################

# sqlite3.c: In function ‘sqlite3SelectNew’:
# vendor/nim-sqlite3-abi/sqlite3.c:124500: warning: function may return address of local variable [-Wreturn-local-addr]
put("sqlite3.always", "-fno-lto") # -Wno-return-local-addr
