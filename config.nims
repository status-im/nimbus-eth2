if defined(release):
  switch("nimcache", "nimcache/release/$projectName")
else:
  switch("nimcache", "nimcache/debug/$projectName")

if defined(windows):
  # disable timestamps in Windows PE headers - https://wiki.debian.org/ReproducibleBuilds/TimestampsInPEBinaries
  switch("passL", "-Wl,--no-insert-timestamp")
  # increase stack size
  switch("passL", "-Wl,--stack,1000000")
  # https://github.com/nim-lang/Nim/issues/4057
  --tlsEmulation:off
  if defined(i386):
    # set the IMAGE_FILE_LARGE_ADDRESS_AWARE flag so we can use PAE, if enabled, and access more than 2 GiB of RAM
    switch("passL", "-Wl,--large-address-aware")

  # The dynamic Chronicles output currently prevents us from using colors on Windows
  # because these require direct manipulations of the stdout File object.
  switch("define", "chronicles_colors=off")

# This helps especially for 32-bit x86, which sans SSE2 and newer instructions
# requires quite roundabout code generation for cryptography, and other 64-bit
# and larger arithmetic use cases, along with register starvation issues. When
# engineering a more portable binary release, this should be tweaked but still
# use at least -msse2 or -msse3.
if defined(disableMarchNative):
  switch("passC", "-msse3")
else:
  switch("passC", "-march=native")
  if defined(windows):
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=65782
    # ("-fno-asynchronous-unwind-tables" breaks Nim's exception raising, sometimes)
    switch("passC", "-mno-avx512vl")

--threads:on
--opt:speed
--excessiveStackTrace:on
# enable metric collection
--define:metrics
--define:chronicles_line_numbers
# for heap-usage-by-instance-type metrics and object base-type strings
--define:nimTypeNames

switch("import", "testutils/moduletests")

# the default open files limit is too low on macOS (512), breaking the
# "--debugger:native" build. It can be increased with `ulimit -n 1024`.
if not defined(macosx):
  # add debugging symbols and original files and line numbers
  --debugger:native
  if not (defined(windows) and defined(i386)) and not defined(disable_libbacktrace):
    # light-weight stack traces using libbacktrace and libunwind
    --define:nimStackTraceOverride
    switch("import", "libbacktrace")

--define:nimOldCaseObjects # https://github.com/status-im/nim-confutils/issues/9

# `switch("warning[CaseTransition]", "off")` fails with "Error: invalid command line option: '--warning[CaseTransition]'"
switch("warning", "CaseTransition:off")

