import stew/io2

type
  ByteChar = byte | char

const INCOMPLETE_ERROR = IoErrorCode(28) # ENOSPC

proc secureCreatePath*(path: string): IoResult[void] =
  when defined(windows):
    let sres = createFoldersUserOnlySecurityDescriptor()
    if sres.isErr():
      error "Could not allocate security descriptor", path = path,
            errorMsg = ioErrorMsg(sres.error), errorCode = $sres.error
      err(sres.error)
    else:
      var sd = sres.get()
      createPath(path, 0o700, secDescriptor = sd.getDescriptor())
  else:
    createPath(path, 0o700)

proc secureWriteFile*[T: ByteChar](path: string,
                                   data: openArray[T]): IoResult[void] =
  when defined(windows):
    let sres = createFilesUserOnlySecurityDescriptor()
    if sres.isErr():
      error "Could not allocate security descriptor", path = path,
            errorMsg = ioErrorMsg(sres.error), errorCode = $sres.error
      err(sres.error())
    else:
      var sd = sres.get()
      let res = writeFile(path, data, 0o600, sd.getDescriptor())
      if res.isErr():
        # writeFile() will not attempt to remove file on failure
        discard removeFile(path)
        err(res.error())
      else:
        ok()
  else:
    let res = writeFile(path, data, 0o600)
    if res.isErr():
      # writeFile() will not attempt to remove file on failure
      discard removeFile(path)
      err(res.error())
    else:
      ok()
