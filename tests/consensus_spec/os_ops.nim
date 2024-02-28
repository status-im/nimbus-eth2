# beacon_chain
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/os
import stew/io2

export walkDir, PathComponent, walkDirRec, walkPattern, `/`, relativePath,
       os.DirSep, os.splitPath
export io2.readAllBytes

proc fileExists*(path: string): bool = io2.isFile(path)

proc dirExists*(path: string): bool = io2.isDir(path)

proc readFile*(filename: string): string =
  let res = io2.readAllChars(filename)
  if res.isErr():
    writeStackTrace()
    try:
      stderr.write "Could not load data from file \"", filename, "\"\n"
      stderr.write "(" & $int(res.error()) & ") ", ioErrorMsg(res.error()), "\n"
    except IOError:
      discard
    quit 1
  res.get()

proc readFileChars*(path: string): string =
  readFile(path)

proc readFileBytes*(path: string): seq[byte] =
  let res = io2.readAllBytes(path)
  if res.isErr():
    writeStackTrace()
    try:
      stderr.write "Could not load data from file \"", path, "\"\n"
      stderr.write "(" & $int(res.error()) & ") ", ioErrorMsg(res.error()), "\n"
    except IOError:
      discard
    quit 1
  res.get()
