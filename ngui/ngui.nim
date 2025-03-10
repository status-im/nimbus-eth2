import std/os

import confutils
import ../beacon_chain/networking/network_metadata

import NimQml
import mainmodel

const
  dothersideDir = currentSourcePath.parentDir & "/../vendor/DOtherSide/"
  corePrivate =
    gorge("pkg-config --variable=includedir Qt5Core") & "/QtCore/" &
    gorge("pkg-config --modversion Qt5Core")
  cflags =
    gorge(
      "pkg-config --cflags --static Qt5Core Qt5Qml Qt5Gui Qt5Quick Qt5QuickControls2 Qt5Widgets"
    ) & " -I" & dothersideDir & "lib/include -I" & corePrivate & " -I" & corePrivate &
    "/QtCore"
  ldflags = gorge "pkg-config --libs --static Qt5Core Qt5Qml Qt5Gui Qt5Quick Qt5QuickControls2 Qt5Widgets"

{.compile(dothersideDir & "lib/src/DOtherSide.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosQMetaObject.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosQDeclarative.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosQObject.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DOtherSideTypesCpp.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosQObjectImpl.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosQAbstractItemModel.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosQQuickImageProvider.cpp", cflags).}
{.compile(dothersideDir & "lib/src/DosLambdaInvoker.cpp", cflags).}

{.passl: ldflags.}

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
