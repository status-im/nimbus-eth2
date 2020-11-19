import json, parseopt, strutils

# Usage: process_dashboard --in=local_dashboard.json --out=remote_dashboard.json --testnet=3 --title="Nimbus Fleet Testnets"

# Import the result on metrics.status.im

var
  p = initOptParser()
  inputFileName, outputFilename: string
  testnet = 0
  title = ""

while true:
  p.next()
  case p.kind:
    of cmdEnd:
      break
    of cmdShortOption, cmdLongOption:
      if p.key == "in":
        inputFileName = p.val
      elif p.key == "out":
        outputFileName = p.val
      elif p.key == "testnet":
        testnet = p.val.parseInt()
      elif p.key == "title":
        title = p.val
      else:
        echo "unsupported argument: ", p.key
    of cmdArgument:
      echo "unsupported argument: ", p.key

var
  inputData = parseFile(inputFileName)
  panels = inputData["panels"].copy()
  outputData = inputData

if title == "":
  title = "Nimbus testnet" & $testnet

#############
# variables #
#############

outputData["templating"]["list"] = parseJson("""
  [
    {
      "allValue": null,
      "current": {
        "tags": [],
        "text": "master-01.aws-eu-central-1a.nimbus.test",
        "value": "master-01.aws-eu-central-1a.nimbus.test"
      },
      "datasource": "legacy-01.do-ams3.public.hq",
      "definition": "label_values(process_virtual_memory_bytes{job=\"beacon-node-metrics\"},instance)",
      "hide": 0,
      "includeAll": false,
      "index": -1,
      "label": null,
      "multi": false,
      "name": "instance",
      "options": [],
      "query": "label_values(process_virtual_memory_bytes{job=\"beacon-node-metrics\"},instance)",
      "refresh": 1,
      "regex": "",
      "skipUrlSync": false,
      "sort": 1,
      "tagValuesQuery": "",
      "tags": [],
      "tagsQuery": "",
      "type": "query",
      "useTags": false
    }
  ]
""")

##########
# panels #
##########

outputData["panels"] = %* []
for panel in panels.mitems:
  panel["title"] = %* replace(panel["title"].getStr(), "${node}", "${instance}")
  panel["datasource"] = newJNull()
  if panel.hasKey("targets"):
    var targets = panel["targets"]
    for target in targets.mitems:
      # The remote Prometheus instance polls once per minute, so the
      # minimum rate() interval is 2 minutes.
      target["expr"] = %* multiReplace(target["expr"].getStr(),
                            ("{node=\"${node}\"}", "{job=\"beacon-node-metrics\",instance=\"${instance}\"}"),
                            ("sum(beacon_attestations_sent_total)", "sum(beacon_attestations_sent_total{job=\"beacon-node-metrics\"})"),
                            ("[2s]", "[2m]"),
                            ("[4s]) * 3", "[2m]) * 120"))
  outputData["panels"].add(panel)

########
# misc #
########

outputData["title"] = %* $title
outputData["uid"] = %* (outputData["uid"].getStr()[0..^2] & $testnet)
# our annotations only work with a 1s resolution
var annotation = outputData["annotations"]["list"][0].copy()
annotation["datasource"] = %* "-- Grafana --"
outputData["annotations"]["list"] = %* [annotation]

writeFile(outputFilename, pretty(outputData))

