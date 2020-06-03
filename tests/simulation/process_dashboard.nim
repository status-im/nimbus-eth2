import json, parseopt, strutils

# usage: process_dashboard --nodes=2 --in=node0_dashboard.json --out=all_nodes_dashboard.json --type=local --testnet=0
type
  OutputType = enum
    local
    remote
var
  p = initOptParser()
  nodes: int
  inputFileName, outputFilename: string
  outputType = OutputType.local
  testnet = 0

let
  hosts = [
    "master-01",
    "node-01",
    "node-02",
    "node-03",
    "node-04",
    "node-05",
    "node-06",
    "node-07",
    "node-08",
    "node-09",
  ]
  nodesPerHost = 2

while true:
  p.next()
  case p.kind:
    of cmdEnd:
      break
    of cmdShortOption, cmdLongOption:
      if p.key == "nodes":
        nodes = p.val.parseInt()
      elif p.key == "in":
        inputFileName = p.val
      elif p.key == "out":
        outputFileName = p.val
      elif p.key == "type":
        outputType = parseEnum[OutputType](p.val)
      elif p.key == "testnet":
        testnet = p.val.parseInt()
      else:
        echo "unsupported argument: ", p.key
    of cmdArgument:
      echo "unsupported argument: ", p.key

var
  inputData = parseFile(inputFileName)
  panels = inputData["panels"].copy()
  numPanels = len(panels)
  gridHeight = 0
  outputData = inputData

for panel in panels:
  if panel["gridPos"]["x"].getInt() == 0:
    gridHeight += panel["gridPos"]["h"].getInt()

outputData["panels"] = %* []
if outputType == OutputType.remote:
  var annotations = outputData["annotations"]["list"]
  for annotation in annotations.mitems:
    annotation["datasource"] = %* "-- Grafana --"

for nodeNum in 0 .. (nodes - 1):
  var
    nodePanels = panels.copy()
    panelIndex = 0
  for panel in nodePanels.mitems:
    panel["title"] = %* replace(panel["title"].getStr(), "#0", "#" & $nodeNum)
    panel["id"] = %* (panelIndex + (nodeNum * numPanels))
    panel["gridPos"]["y"] = %* (panel["gridPos"]["y"].getInt() + (nodeNum * gridHeight))
    if outputType == OutputType.remote:
      panel["datasource"] = newJNull()
    if panel.hasKey("targets"):
      var targets = panel["targets"]
      for target in targets.mitems:
        case outputType:
          of OutputType.local:
            target["expr"] = %* replace(target["expr"].getStr(), "{node=\"0\"}", "{node=\"" & $nodeNum & "\"}")
          of OutputType.remote:
            # The remote Prometheus instance polls once per minute, so the
            # minimum rate() interval is 2 minutes.
            target["expr"] = %* multiReplace(target["expr"].getStr(),
                                  ("{node=\"0\"}", "{container=\"beacon-node-testnet" & $testnet & "-" & $((nodeNum mod 2) + 1) & "\",instance=\"" & (hosts[nodeNum div nodesPerHost]) & ".aws-eu-central-1a.nimbus.test\"}"),
                                  ("[2s]", "[2m]"),
                                  ("[4s]) * 3", "[2m]) * 120"))
    outputData["panels"].add(panel)
    panelIndex.inc()

case outputType:
  of OutputType.local:
    outputData["title"] = %* (outputData["title"].getStr() & " (all nodes)")
    outputData["uid"] = %* (outputData["uid"].getStr() & "a")
  of OutputType.remote:
    outputData["title"] = %* ("Nimbus testnet" & $testnet)
    outputData["uid"] = %* (outputData["uid"].getStr() & $testnet)
writeFile(outputFilename, pretty(outputData))

