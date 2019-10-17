import json, parseopt, strutils

# usage: process_dashboard --nodes=2 --in=node0_dashboard.json --out=all_nodes_dashboard.json
var
  p = initOptParser()
  nodes: int
  inputFileName, outputFilename: string

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
for nodeNum in 0 .. (nodes - 1):
  var
    nodePanels = panels.copy()
    panelIndex = 0
  for panel in nodePanels.mitems:
    panel["title"] = %* replace(panel["title"].getStr(), "#0", "#" & $nodeNum)
    panel["id"] = %* (panelIndex + (nodeNum * numPanels))
    panel["gridPos"]["y"] = %* (panel["gridPos"]["y"].getInt() + (nodeNum * gridHeight))
    var targets = panel["targets"]
    for target in targets.mitems:
      target["expr"] = %* replace(target["expr"].getStr(), "{node=\"0\"}", "{node=\"" & $nodeNum & "\"}")
    outputData["panels"].add(panel)
    panelIndex.inc()

outputData["uid"] = %* (outputData["uid"].getStr() & "a")
outputData["title"] = %* (outputData["title"].getStr() & " (all nodes)")
writeFile(outputFilename, pretty(outputData))

