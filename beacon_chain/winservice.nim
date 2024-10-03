# beacon_chain
# Copyright (c) 2023-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Everything needed to run beacon node as Windows service.

when defined(windows):
  import results, chronicles
  import chronos/[osdefs, osutils, oserrno]
  import ./conf_common

  type
    SERVICE_STATUS* {.final, pure.} = object
      dwServiceType*: DWORD
      dwCurrentState*: DWORD
      dwControlsAccepted*: DWORD
      dwWin32ExitCode*: DWORD
      dwServiceSpecificExitCode*: DWORD
      dwCheckPoint*: DWORD
      dwWaitHint*: DWORD

    SERVICE_STATUS_HANDLE* = DWORD
    LPSERVICE_STATUS* = ptr SERVICE_STATUS
    LPSERVICE_MAIN_FUNCTIONW* = proc (para1: DWORD, para2: LPWSTR) {.stdcall.}

    SERVICE_TABLE_ENTRYW* {.final, pure.} = object
      lpServiceName*: LPWSTR
      lpServiceProc*: LPSERVICE_MAIN_FUNCTIONW

    LPSERVICE_TABLE_ENTRYW* = ptr SERVICE_TABLE_ENTRYW
    LPHANDLER_FUNCTION* = proc (para1: DWORD): WINBOOL {.stdcall.}

  const
    SERVICE_WIN32_OWN_PROCESS = 16
    SERVICE_RUNNING = 4
    SERVICE_STOPPED = 1
    SERVICE_START_PENDING = 2
    SERVICE_STOP_PENDING = 3
    SERVICE_CONTROL_STOP = 1
    SERVICE_CONTROL_PAUSE = 2
    SERVICE_CONTROL_CONTINUE = 3
    SERVICE_CONTROL_INTERROGATE = 4
    SERVICE_ACCEPT_STOP = 1
    ERROR_INVALID_PARAMETER = 87
    ERROR_BAD_CONFIGURATION = 1610
    NO_ERROR = 0

  var
    gSvcStatusHandle: SERVICE_STATUS_HANDLE
    gSvcStatus: SERVICE_STATUS

  proc startServiceCtrlDispatcher(
         lpServiceStartTable: LPSERVICE_TABLE_ENTRYW
       ): WINBOOL {.
       stdcall, dynlib: "advapi32", importc: "StartServiceCtrlDispatcherW".}

  proc setServiceStatus(
         hServiceStatus: SERVICE_STATUS_HANDLE,
         lpServiceStatus: LPSERVICE_STATUS
       ): WINBOOL {.
       stdcall, dynlib: "advapi32", importc: "SetServiceStatus".}

  proc registerServiceCtrlHandler(
         lpServiceName: LPWSTR,
         lpHandlerProc: LPHANDLER_FUNCTION
       ): SERVICE_STATUS_HANDLE {.
       stdcall, dynlib: "advapi32", importc: "RegisterServiceCtrlHandlerW".}

  proc getCommandLine(dwArgc: DWORD,
                      lpszArgv: LPWSTR): Result[seq[string], string] =
    var res: seq[string]
    let arguments = cast[ptr UncheckedArray[LPWSTR]](lpszArgv)
    if uint64(dwArgc) > uint64(high(int)):
      return err("Unable to process incredible count of arguments")
    for i in 0 ..< int(dwArgc):
      let str = arguments[i].toString().valueOr:
        return err("Unable to process arguments, reason: " & osErrorMsg(error))
      res.add(str)
    ok(res)

  proc reportServiceStatus(dwCurrentState, dwWin32ExitCode,
                           dwWaitHint: DWORD) {.gcsafe.} =
    gSvcStatus.dwCurrentState = dwCurrentState
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode
    gSvcStatus.dwWaitHint = dwWaitHint
    if dwCurrentState == SERVICE_START_PENDING:
      gSvcStatus.dwControlsAccepted = 0
    else:
      gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP

    # TODO
    # We can use non-zero values for the `dwCheckPoint` parameter to report
    # progress during lengthy operations such as start-up and shut down.
    gSvcStatus.dwCheckPoint = 0

    # Report the status of the service to the SCM.
    let status = setServiceStatus(gSvcStatusHandle, addr gSvcStatus)
    debug "Service status updated", status

  proc reportServiceStatusSuccess*() =
    reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0)

  template establishWindowsService*(argClientId,
                                    argCopyrights,
                                    argNimBanner,
                                    argSpecVersion,
                                    argServiceName: string,
                                    argConfigType: untyped,
                                    argEntryPoint: untyped,
                                    argExitPoint: untyped): untyped =

    proc serviceControlHandler(dwCtrl: DWORD): WINBOOL {.stdcall.} =
      case dwCtrl
      of SERVICE_CONTROL_STOP:
        # We're reporting that we plan to stop the service in 10 seconds
        reportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 10_000)
        argExitPoint()
      of SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_CONTINUE:
        warn "The Nimbus service cannot be paused and resimed"
      of SERVICE_CONTROL_INTERROGATE:
        # The default behavior is correct.
        # The service control manager will report our last status.
        discard
      else:
        debug "Service received an unexpected user-defined control message",
              msg = dwCtrl

    proc serviceMainFunction(dwArgc: DWORD, lpszArgv: LPWSTR) {.stdcall.} =
      # The service is launched in a fresh thread created by Windows, so
      # we must initialize the Nim GC here
      let serviceName = newWideCString(argServiceName)

      setupForeignThreadGc()

      gSvcStatusHandle = registerServiceCtrlHandler(
        cast[LPWSTR](serviceName),
        serviceControlHandler)

      gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS
      gSvcStatus.dwServiceSpecificExitCode = 0
      reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0)

      let environment = getCommandLine(dwArgc, lpszArgv).valueOr:
        reportServiceStatus(SERVICE_STOPPED, ERROR_INVALID_PARAMETER, 0)
        quit QuitFailure

      var config = makeBannerAndConfig(argClientId, argCopyrights,
                                       argNimBanner, argSpecVersion,
                                       environment, argConfigType).valueOr:
        reportServiceStatus(SERVICE_STOPPED, ERROR_BAD_CONFIGURATION, 0)
        quit QuitFailure

      try:
        argEntryPoint(config)
        info "Service thread stopped"
        # we have to report back when we stopped!
        reportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0)
      except CatchableError:
        info "Service thread crashed"
        # we have to report back when we stopped!
        reportServiceStatus(SERVICE_STOPPED, ERROR_INVALID_ACCESS, 0)

    let serviceName = newWideCString(argServiceName)

    var dispatchTable = [
      SERVICE_TABLE_ENTRYW(lpServiceName: cast[LPWSTR](serviceName),
                           lpServiceProc: serviceMainFunction),
      SERVICE_TABLE_ENTRYW(lpServiceName: nil,
                           lpServiceProc: nil)
    ]

    let status =
      startServiceCtrlDispatcher(LPSERVICE_TABLE_ENTRYW(addr dispatchTable[0]))
    if status == 0:
      let errorCode = osLastError()
      fatal "Failed to start Windows service", error_code = uint32(errorCode),
            reason = osErrorMsg(errorCode)
      quit QuitFailure
