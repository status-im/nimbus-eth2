import std/os

import confutils
import ../beacon_chain/networking/network_metadata

import NimQml
import mainmodel

const cflags = gorge("pkg-config --cflags --static Qt5Core")

static:
  discard staticExec(
    "rcc " & currentSourcePath.parentDir & "/resources.qrc -o " &
      currentSourcePath.parentDir & "/resources.cpp"
  )
{.compile(currentSourcePath.parentDir & "/resources.cpp", cflags).}

proc mainProc(url, network: string) =
  let app = newQApplication()
  defer:
    app.delete
  let cfg = getMetadataForNetwork(network).cfg
  let main = newMainModel(app, url, cfg)
  defer:
    main.delete

  let engine = newQQmlApplicationEngine()
  defer:
    engine.delete

  let mainVariant = newQVariant(main)
  defer:
    mainVariant.delete

  engine.setRootContextProperty("main", mainVariant)

  engine.addImportPath("qrc:/")
  engine.load(newQUrl("qrc:/ui/main.qml"))
  app.exec()

when isMainModule:
  cli do(url = "http://localhost:5052", network = "mainnet"):
    mainProc(url, network)
    GC_fullcollect()
