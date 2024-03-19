import stew/io2
import spec/keystore

type
  ByteChar = byte | char

const INCOMPLETE_ERROR = IoErrorCode(28) # ENOSPC

proc openLockedFile*(keystorePath: string): IoResult[FileLockHandle] =
  let
    flags = {OpenFlags.Read, OpenFlags.Write, OpenFlags.Exclusive}
    handle = ? openFile(keystorePath, flags)

  var success = false
  defer:
    if not(success):
      discard closeFile(handle)

  let lock = ? lockFile(handle, LockType.Exclusive)
  success = true
  ok(FileLockHandle(ioHandle: lock, opened: true))

proc getData*(lockHandle: FileLockHandle,
              maxBufferSize: int): IoResult[string] =
  let filesize = ? getFileSize(lockHandle.ioHandle.handle)
  let length = min(filesize, maxBufferSize)
  var buffer = newString(length)
  let bytesRead = ? readFile(lockHandle.ioHandle.handle, buffer)
  if uint64(bytesRead) != uint64(len(buffer)):
    err(INCOMPLETE_ERROR)
  else:
    ok(buffer)

proc closeLockedFile*(lockHandle: FileLockHandle): IoResult[void] =
  if lockHandle.opened:
    var success = false
    defer:
      lockHandle.opened = false
      if not(success):
        discard lockHandle.ioHandle.handle.closeFile()

    ? lockHandle.ioHandle.unlockFile()
    success = true
    ? lockHandle.ioHandle.handle.closeFile()
  ok()

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
