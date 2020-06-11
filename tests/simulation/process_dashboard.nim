import json, parseopt, strutils

# usage: process_dashboard --in=node0_dashboard.json --out=all_nodes_dashboard.json --type=local --testnet=0
type
  OutputType = enum
    local
    remote
var
  p = initOptParser()
  inputFileName, outputFilename: string
  outputType = OutputType.local
  testnet = 0

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
  outputData = inputData

#############
# variables #
#############

case outputType:
  of OutputType.local:
    outputData["templating"]["list"] = parseJson("""
      [
        {
          "allValue": null,
          "current": {
            "tags": [],
            "text": "0",
            "value": "0"
          },
          "datasource": "Prometheus",
          "definition": "label_values(process_virtual_memory_bytes,node)",
          "hide": 0,
          "includeAll": false,
          "index": -1,
          "label": null,
          "multi": false,
          "name": "node",
          "options": [],
          "query": "label_values(process_virtual_memory_bytes,node)",
          "refresh": 1,
          "regex": "",
          "skipUrlSync": false,
          "sort": 0,
          "tagValuesQuery": "",
          "tags": [],
          "tagsQuery": "",
          "type": "query",
          "useTags": false
        }
      ]
    """)
  of OutputType.remote:
    outputData["templating"]["list"] = parseJson("""
      [
        {
          "allValue": null,
          "current": {
            "tags": [],
            "text": "beacon-node-testnet""" & $testnet & """-1",
            "value": "beacon-node-testnet""" & $testnet & """-1"
          },
          "datasource": "master-01.do-ams3.metrics.hq",
          "definition": "label_values(process_virtual_memory_bytes{job=\"beacon-node-metrics\"},container)",
          "hide": 0,
          "includeAll": false,
          "index": -1,
          "label": null,
          "multi": false,
          "name": "container",
          "options": [],
          "query": "label_values(process_virtual_memory_bytes{job=\"beacon-node-metrics\"},container)",
          "refresh": 1,
          "regex": "/.*testnet""" & $testnet & """.*/",
          "skipUrlSync": false,
          "sort": 1,
          "tagValuesQuery": "",
          "tags": [],
          "tagsQuery": "",
          "type": "query",
          "useTags": false
        },
        {
          "allValue": null,
          "current": {
            "tags": [],
            "text": "master-01.aws-eu-central-1a.nimbus.test",
            "value": "master-01.aws-eu-central-1a.nimbus.test"
          },
          "datasource": "master-01.do-ams3.metrics.hq",
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
  case outputType:
    of OutputType.local:
      panel["title"] = %* replace(panel["title"].getStr(), "#0", "#${node}")
    of OutputType.remote:
      panel["title"] = %* replace(panel["title"].getStr(), "#0", "#${container}@${instance}")
      panel["datasource"] = newJNull()
  if panel.hasKey("targets"):
    var targets = panel["targets"]
    for target in targets.mitems:
      case outputType:
        of OutputType.local:
          target["expr"] = %* replace(target["expr"].getStr(), "{node=\"0\"}", "{node=\"${node}\"}")
        of OutputType.remote:
          # The remote Prometheus instance polls once per minute, so the
          # minimum rate() interval is 2 minutes.
          target["expr"] = %* multiReplace(target["expr"].getStr(),
                                ("{node=\"0\"}", "{job=\"beacon-node-metrics\",container=\"${container}\",instance=\"${instance}\"}"),
                                ("sum(beacon_attestations_sent_total)", "sum(beacon_attestations_sent_total{job=\"beacon-node-metrics\",container=~\"beacon-node-testnet" & $testnet & "-.\"})"),
                                ("[2s]", "[2m]"),
                                ("[4s]) * 3", "[2m]) * 120"))
  outputData["panels"].add(panel)

########
# misc #
########

case outputType:
  of OutputType.local:
    outputData["title"] = %* "NBC local testnet/sim (all nodes)"
    outputData["uid"] = %* (outputData["uid"].getStr() & "a")
  of OutputType.remote:
    outputData["title"] = %* ("Nimbus testnet" & $testnet)
    outputData["uid"] = %* (outputData["uid"].getStr() & $testnet)
    # our annotations only work with a 1s resolution
    var annotation = outputData["annotations"]["list"][0].copy()
    annotation["datasource"] = %* "-- Grafana --"
    outputData["annotations"]["list"] = %* [annotation]

writeFile(outputFilename, pretty(outputData))

