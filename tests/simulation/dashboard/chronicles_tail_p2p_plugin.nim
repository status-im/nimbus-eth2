import
  strformat, jsconsole, jsffi,
  karax/[karax, kdom, karaxdsl, vdom],
  chronicles_tail/jsplugins

# Make sure that the Karax instance in the plugin is the same one
# as the Karax instance in the enclosing chronicle-tail page.
kxi = getKarax()

type EventsTable = ref object of VComponent

proc renderNetworkEvents(page: VComponent): VNode =
  result = buildHtml:
    table:
      tr:
        th: text "Time"
        th: text "Nodes"

const
  columnWidth = 320
  timestampsHeight = 50
  eventsMargin = 10

var
  eventsTable = newComponent(EventsTable, renderNetworkEvents)
  protocolMessages = newJsAssoc[cstring, JsAssoc[cstring, cstring]]()

  pendingEvents = newSeq[TailEvent]()
  freedColumns = newSeq[int]()
  columnBottoms = newSeq[int]()
  peerToColumnTable = newJsAssoc[cstring, int]()
  lastTimestampBottom = timestampsHeight

proc startsWith*(a, b: cstring): bool {.importcpp: "startsWith", nodecl.}

proc getMsgName(protocol: cstring, msgId: int): cstring =
  protocolMessages[protocol][cast[cstring](msgId)]

proc renderEvent(ev: TailEvent): cstring =
  var res = newStringOfCap(1024)
  let eventType = ev.msg

  res.add &"""<div class="event {eventType}">"""

  template addField(class, value) =
    res.add "<div class=\"" & class & "\">"
    res.addEscaped $value
    res.add "</div>"

  if eventType.startsWith(cstring("peer_")):
    addField "peer", ev.peer
    addField "port", ev.port
  else:
    addField "msgName", getMsgName(ev.protocol, ev.msgId)
    res.addAsHtml ev.data

  res.add """</div>"""
  return cstring(res)

proc selectColumn(ev: TailEvent): int =
  let key = cast[cstring](ev.port)# & ev.peer
  kout ev.msg, key

  if ev.msg in [cstring"peer_accepted", "peer_connected"]:
    if freedColumns.len > 0:
      result = freedColumns.pop()
    else:
      result = columnBottoms.len
      columnBottoms.add(timestampsHeight)
    peerToColumnTable[key] = result

  elif ev.msg == cstring("peer_disconnected"):
    result = peerToColumnTable[key]
    discard jsDelete peerToColumnTable[key]
    freedColumns.add result

  else:
    result = peerToColumnTable[key]

template pixels(n: int): cstring =
  cast[cstring](n) & "px"

proc addEvent(ev: TailEvent) =
  var
    row = document.createElement("tr")
    timeElem = document.createElement("td")
    eventElem = document.createElement("td")
    eventsTable = eventsTable.dom
    eventsCount = eventsTable.children.len
    lastEventRow = eventsTable.children[eventsCount - 1]

  row.class = if eventsCount mod 2 == 0: "even" else: "odd"

  # Hide the element initially, so we can safely measure its size.
  # It has to be added to the DOM before it can be measured.
  row.style.visibility = "hidden"
  row.appendChild(timeElem)
  row.appendChild(eventElem)

  timeElem.innerHtml = ev.ts
  timeElem.class = "time"

  eventElem.innerHTML = renderEvent(ev)

  eventsTable.appendChild(row)
  let rowHeight = row.offsetHeight
  let eventColumn = selectColumn(ev)
  let timestampOffset = max(lastTimestampBottom, columnBottoms[eventColumn])
  let prevTimestampOffset = lastTimestampBottom - timestampsHeight

  lastTimestampBottom = timestampOffset + timestampsHeight
  columnBottoms[eventColumn] += rowHeight + eventsMargin

  # Make sure the event data is in the right column and that it
  # can overflow past the row height:
  eventElem.style.paddingLeft = pixels(eventColumn * columnWidth)

  # Position the row in its right place and show it:
  lastEventRow.style.height = pixels(timestampOffset - prevTimestampOffset)
  row.style.top = pixels(timestampOffset)
  row.style.visibility = ""

proc networkSectionContent: VNode =
  result = buildHtml(tdiv(id = "network")):
    text "Network section"
    eventsTable

proc tailEventFilter(ev: TailEvent): bool =
  if ev.topics != "p2pdump":
    return false

  if ev.msg == "p2p_protocols":
    protocolMessages = cast[type(protocolMessages)](ev.data)
  else:
    if eventsTable.dom == nil:
      pendingEvents.add ev
    else:
      addEvent ev

  return true

proc addPending =
  if eventsTable.dom != nil and pendingEvents.len > 0:
    defer: pendingEvents.setLen(0)
    for ev in pendingEvents:
      addEvent ev

let interval = window.setInterval(addPending, 1000)

proc addStyles(styles: cstring) =
  var s = document.createElement("style")
  s.appendChild document.createTextNode(styles)
  document.head.appendChild(s)

once:
  addStyles cstring"""
    #network > table {
      position: relative;
    }

    #network .event {
      border: 1px solid blue;
    }

    #network .event table {
      width: 100%;
    }

    #network > table > tr {
      position: absolute;
      display: flex;
      flex-direction: row;
      border-left: 1px solid red;
    }

    #network .time {
      width: 160px;
    }

    #network .event {
      width: 320px;
    }
  """

  addSection("Network", networkSectionContent)
  addEventFilter(tailEventFilter)

kxi.redraw()

