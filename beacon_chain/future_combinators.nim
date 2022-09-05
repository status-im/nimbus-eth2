# TODO: These should be added to the Chronos's asyncfutures2 module
#       See https://github.com/status-im/nim-chronos/pull/339

import
  chronos

proc firstCompletedFuture*(futs: varargs[FutureBase]): Future[FutureBase] =
  ## Returns a future which will complete and return completed FutureBase,
  ## when one of the futures in ``futs`` is completed.
  ##
  ## If the argument is empty, the returned future FAILS immediately.
  ##
  ## On success, the returned Future will hold the completed FutureBase.
  ##
  ## If all futures fail naturally or due to cancellation, the returned
  ## future will be failed as well.
  ##
  ## On cancellation, futures in ``futs`` WILL NOT BE cancelled.

  var retFuture = newFuture[FutureBase]("chronos.firstCompletedFuture()")

  # Because we can't capture varargs[T] in closures we need to create copy.
  var nfuts = @futs

  # If one of the Future[T] already finished we return it as result
  for fut in nfuts:
    if fut.completed():
      retFuture.complete(fut)
      return retFuture

  if len(nfuts) == 0:
    retFuture.fail(newException(ValueError, "Empty Future[T] list"))
    return

  var failedFutures = 0

  var cb: proc(udata: pointer) {.gcsafe, raises: [Defect].}
  cb = proc(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not(retFuture.finished()):
      var res: FutureBase
      var rfut = cast[FutureBase](udata)
      if rfut.completed:
        for i in 0..<len(nfuts):
          if nfuts[i] != rfut:
            nfuts[i].removeCallback(cb)
          else:
            res = nfuts[i]
        retFuture.complete(res)
      else:
        inc failedFutures
        if failedFutures == nfuts.len:
          retFuture.fail(newException(CatchableError,
            "None of the operations completed successfully"))

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    for i in 0..<len(nfuts):
      if not(nfuts[i].finished()):
        nfuts[i].removeCallback(cb)

  for fut in nfuts:
    fut.addCallback(cb, cast[pointer](fut))

  retFuture.cancelCallback = cancellation
  return retFuture

proc firstCompleted*[T](futs: varargs[Future[T]]): Future[T] =
  ## On success, the returned Future will hold the result of the first
  ## completed imput Future.
  ##
  ## If the varargs list is empty, the returned future FAILS immediately.
  ##
  ## If all futures fail naturally or due to cancellation, the returned
  ## future will be failed as well.
  ##
  ## On cancellation, futures in ``futs`` WILL NOT BE cancelled.

  let subFuture = firstCompletedFuture(futs)
  if subFuture.completed:
    return Future[T](subFuture.read)

  var retFuture = newFuture[T]("chronos.firstCompleted()")

  if subFuture.finished: # It must be failed ot cancelled
    retFuture.fail(subFuture.error)
    return retFuture

  proc cb(udata: pointer) {.gcsafe, raises: [Defect].} =
    let subFuture = cast[Future[FutureBase]](udata)
    if subFuture.completed:
      retFuture.complete(Future[T](subFuture.read).read)
    else:
      retFuture.fail(subFuture.error)

  subFuture.addCallback(cb, cast[pointer](subFuture))

  retFuture.cancelCallback = proc (udata: pointer) =
    subFuture.cancel()
