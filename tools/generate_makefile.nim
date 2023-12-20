# Copyright (c) 2020-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Generate a Makefile from the JSON file produce by the Nim compiler with
# "--compileOnly". Suitable for Make-controlled parallelisation, down to the GCC
# LTO level.

import json, os, strutils

# Ripped off from Nim's `linkViaResponseFile()` in "compiler/extccomp.nim".
# It lets us get around a command line length limit on Windows.
proc processLinkCmd(cmd, linkerArgs: string): string =
  # Extracting the linker.exe here is a bit hacky but the best solution
  # given ``buildLib``'s design.
  var
    i = 0
    last = 0

  if cmd.len > 0 and cmd[0] == '"':
    inc i
    while i < cmd.len and cmd[i] != '"':
      inc i
    last = i
    inc i
  else:
    while i < cmd.len and cmd[i] != ' ':
      inc i
    last = i

  while i < cmd.len and cmd[i] == ' ':
    inc i

  let args = cmd.substr(i)
  writeFile(linkerArgs, args.replace('\\', '/'))

  return cmd.substr(0, last) & " @" & linkerArgs

proc main() =
  let nrParams = paramCount()

  if nrParams != 2:
    echo "Usage: ", paramStr(0), " input.json output.makefile"
    quit(QuitFailure)

  let
    jsonPath = paramStr(1)
    makefilePath = paramStr(2)

  if not fileExists(jsonPath):
    echo "No such file: ", jsonPath
    quit(QuitFailure)

  let
    data = json.parseFile(jsonPath)
    makefile = open(makefilePath, fmWrite)

  defer:
    makefile.close()

  var
    objectPath: string
    found: bool
    cmd: string

  for compile in data["compile"]:
    cmd = compile[1].getStr().replace('\\', '/')
    objectPath = ""
    found = false
    for token in split(cmd, Whitespace + {'\''}):
      if found and token.len > 0 and token.endsWith(".o"):
        objectPath = token
        break
      if token == "-o":
        found = true
    if found == false or objectPath == "":
      echo "Could not find the object file in this command: ", cmd
      quit(QuitFailure)
    makefile.writeLine(
      "$#: $#" % [objectPath.replace('\\', '/'), compile[0].getStr().replace('\\', '/')]
    )
    makefile.writeLine("\t+ $#\n" % cmd)

  var objects: seq[string]
  for obj in data["link"]:
    objects.add(obj.getStr().replace('\\', '/'))
  makefile.writeLine("OBJECTS := $#\n" % objects.join(" \\\n"))

  makefile.writeLine(".PHONY: build")
  makefile.writeLine("build: $(OBJECTS)")
  makefile.writeLine(
    "\t+ $#" %
      processLinkCmd(
        data["linkcmd"].getStr().replace('\\', '/'), makefilePath & ".linkerArgs"
      )
  )
  if data.hasKey("extraCmds"):
    for cmd in data["extraCmds"]:
      makefile.writeLine("\t+ $#" % cmd.getStr().replace('\\', '/'))

main()
