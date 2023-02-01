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
    stderr.write "Could not load data from file \"", filename, "\"\n"
    stderr.write "(" & $int(res.error()) & ") " & ioErrorMsg(res.error()), "\n"
    quit 1
  res.get()

proc readFileChars*(path: string): string =
  readFile(path)

proc readFileBytes*(path: string): seq[byte] =
  let res = io2.readAllBytes(path)
  if res.isErr():
    writeStackTrace()
    stderr.write "Could not load data from file \"", path, "\"\n"
    stderr.write "(" & $int(res.error()) & ") " & ioErrorMsg(res.error()), "\n"
    quit 1
  res.get()
