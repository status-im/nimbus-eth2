# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# REST utilities common across several nimbus binaries (BN/VC/EC/Portal/etc)

import metrics/chronos_httpserver, presto

from stew/io2 import readAllChars

proc init*(T: type RestServerRef,
           ip: IpAddress,
           port: Port,
           allowedOrigin: Option[string],
           validateFn: PatternCallback,
           ident: string,
           config: auto): T =
  let
    address = initTAddress(ip, port)
    serverFlags = {HttpServerFlags.QueryCommaSeparatedArray,
                   HttpServerFlags.NotifyDisconnect}
  # We increase default timeout to help validator clients who poll our server
  # at least once per slot (12.seconds).
  let
    headersTimeout =
      if config.restRequestTimeout == 0:
        chronos.InfiniteDuration
      else:
        seconds(int64(config.restRequestTimeout))
    maxHeadersSize = config.restMaxRequestHeadersSize * 1024
    maxRequestBodySize = config.restMaxRequestBodySize * 1024

  let res = RestServerRef.new(RestRouter.init(validateFn, allowedOrigin),
                              address, serverFlags = serverFlags,
                              serverIdent = ident,
                              httpHeadersTimeout = headersTimeout,
                              maxHeadersSize = maxHeadersSize,
                              maxRequestBodySize = maxRequestBodySize,
                              errorType = string)
  if res.isErr():
    notice "REST HTTP server could not be started", address = $address,
           reason = res.error()
    nil
  else:
    let server = res.get()
    notice "Starting REST HTTP server", url = "http://" & $server.localAddress()
    server

type
  KeymanagerInitResult* = object
    server*: RestServerRef
    token*: string

proc initKeymanagerServer*(
    config: auto,
    existingRestServer: RestServerRef = nil): KeymanagerInitResult
    {.raises: [].} =

  var token: string
  let keymanagerServer = if config.keymanagerEnabled:
    if config.keymanagerTokenFile.isNone:
      echo "To enable the Keymanager API, you must also specify " &
           "the --keymanager-token-file option."
      quit 1

    let
      tokenFilePath = config.keymanagerTokenFile.get.string
      tokenFileReadRes = readAllChars(tokenFilePath)

    if tokenFileReadRes.isErr:
      fatal "Failed to read the keymanager token file",
            error = $tokenFileReadRes.error
      quit 1

    token = tokenFileReadRes.value.strip
    if token.len == 0:
      fatal "The keymanager token should not be empty", tokenFilePath
      quit 1

    when compiles(config.restPort):
      if existingRestServer != nil and
         config.restAddress == config.keymanagerAddress and
        config.restPort == config.keymanagerPort:
        existingRestServer
      else:
        RestServerRef.init(config.keymanagerAddress, config.keymanagerPort,
                           config.keymanagerAllowedOrigin,
                           validateKeymanagerApiQueries,
                           nimbusAgentStr,
                           config)
    else:
      RestServerRef.init(config.keymanagerAddress, config.keymanagerPort,
                         config.keymanagerAllowedOrigin,
                         validateKeymanagerApiQueries,
                         nimbusAgentStr,
                         config)
  else:
    nil

  KeymanagerInitResult(server: keymanagerServer, token: token)

proc initMetricsServer*(
    config: auto
): Future[Result[Opt[MetricsHttpServerRef], string]] {.
  async: (raises: [CancelledError]).} =
  if config.metricsEnabled:
    let
      metricsAddress = config.metricsAddress
      metricsPort = config.metricsPort
      url = "http://" & $metricsAddress & ":" & $metricsPort & "/metrics"

    info "Starting metrics HTTP server", url = url

    let server = MetricsHttpServerRef.new($metricsAddress, metricsPort).valueOr:
      fatal "Could not start metrics HTTP server",
            url = url, reason = error
      return err($error)

    try:
      await server.start()
    except MetricsError as exc:
      fatal "Could not start metrics HTTP server",
            url = url, reason = exc.msg
      return err(exc.msg)

    ok(Opt.some(server))
  else:
    ok(Opt.none(MetricsHttpServerRef))

proc stopMetricsServer*(v: Opt[MetricsHttpServerRef]) {.
     async: (raises: []).} =
  if v.isSome():
    info "Shutting down metrics HTTP server"
    await v.get().close()
