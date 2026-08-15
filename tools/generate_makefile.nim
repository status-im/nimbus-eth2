# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Generate a Makefile from the JSON file produced by the Nim compiler with
# "--compileOnly". Suitable for Make-controlled parallelisation, down to the GCC
# LTO level.

import std/[cmdline, json, os, strutils]

# Ripped off from Nim's `linkViaResponseFile()` in "compiler/extccomp.nim".
# It lets us get around a command line length limit on Windows.
proc processLinkCmd(cmd, linkerArgs: string): string {.raises: [IOError].} =
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
    data =
      try:
        json.parseFile(jsonPath)
      except IOError as exc:
        echo "Failed to parse file: ", jsonPath, " - [IOError]: ", exc.msg
        quit(QuitFailure)
      except Exception as exc:
        echo "Failed to parse file: ", jsonPath, " - [Exception]: ", exc.msg
        quit(QuitFailure)
    makefile =
      try:
        open(makefilePath, fmWrite)
      except IOError as exc:
        echo "Failed to open file: ", makefilePath, " - [IOError]: ", exc.msg
        quit(QuitFailure)

  defer:
    makefile.close()

  var
    objects: seq[string]
    cmd: string

  try:
    try:
      for compile in data["compile"]:
        cmd = compile[1].getStr().replace('\\', '/')
        var
          next = false
          found = false
        for token in parseCmdLine(cmd):
          if next:
            if token.len > 0 and token.endsWith(".o"):
              makefile.writeLine(token & ":")
              makefile.writeLine("\t " & cmd)

              objects.add token
              found = true
            break

          if token == "-o":
            next = true

        if not found:
          echo "Could not find the object file in this command: ", cmd
          quit(QuitFailure)
    except KeyError:
      echo "File lacks `compile` key: ", jsonPath
      quit(QuitFailure)


    makefile.writeLine("OBJECTS := " & objects.join(" \\\n"))

    # The json instructions contain exactly the files that need to be rebuilt
    # (ie source modified / flags changed etc) so we mark all objects PHONY to
    # force them to be rebuilt
    # TODO change detection does not deeply cover changes in C file includes etc
    makefile.writeLine(".PHONY: build $(OBJECTS)")
    makefile.writeLine("build: $(OBJECTS)")

    let linkerArgs = makefilePath & ".linkerArgs"
    try:
      # + ensures the jobserver protocol is active in the linker command, for
      # LTO + jobserver purposes
      makefile.writeLine(
        "\t+ " & processLinkCmd(data["linkcmd"].getStr().replace('\\', '/'), linkerArgs)
      )
    except IOError as exc:
      echo "Failed to write file: ", linkerArgs, " - [IOError]: ", exc.msg
      quit(QuitFailure)
    except KeyError as exc:
      echo "Missing linkcmd"
      quit(QuitFailure)

    if data.hasKey("extraCmds"):
      try:
        for cmd in data["extraCmds"]:
          try:
            makefile.writeLine("\t+ $#" % cmd.getStr().replace('\\', '/'))
          except ValueError:
            # https://github.com/nim-lang/Nim/pull/23356
            raiseAssert "Arguments match the format string"
      except KeyError:
        raiseAssert "just checked"
  except IOError as exc:
    echo "Failed to write file: ", makefilePath, " - [IOError]: ", exc.msg
    quit(QuitFailure)

main()
