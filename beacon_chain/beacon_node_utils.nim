import
  spec/datatypes, beacon_node_types

proc onBeaconBlock*(node: BeaconNode, blck: BeaconBlock) {.gcsafe.}