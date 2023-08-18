# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[strutils, parseutils, sequtils, terminal, colors]

type
  ContentFragments = seq[tuple[kind: InterpolatedKind, value: string]]

  StatusBarCell = object
    label, content: string
    contentFragments: ContentFragments

  Layout = object
    cellsLeft: seq[StatusBarCell]
    cellsRight: seq[StatusBarCell]

  DataItemResolver* = proc (dataItem: string): string {.
    gcsafe, raises: [Defect].}

  StatusBarView* = object
    model: DataItemResolver
    layout: Layout
    consumedLines: int

const
  sepLeft  = "❯"
  sepRight = "❮"

  # sepLeft  = "|"
  # sepRight = "|"

  backgroundColor = rgb(36, 36, 36)
  foregroundColor = colWhiteSmoke

func loadFragmentsLayout(contentLayout: string): ContentFragments {.
    raises: [Defect, ValueError].} =
  toSeq(interpolatedFragments(strip contentLayout))

func loadCellsLayout(cellsLayout: string): seq[StatusBarCell] {.
    raises: [Defect, ValueError].} =
  let cells = cellsLayout.split(';')
  for cell in cells:
    let columns = cell.split(':', maxSplit = 1)
    if columns.len == 2:
      result.add StatusBarCell(
        label: strip(columns[0]),
        contentFragments: loadFragmentsLayout(columns[1]))
    else:
      result.add StatusBarCell(
        contentFragments: loadFragmentsLayout(columns[0]))

func loadLayout(layout: string): Layout {.raises: [Defect, ValueError].} =
  let sections = layout.split('|', maxSplit = 1)
  result.cellsLeft = loadCellsLayout(sections[0])
  if sections.len == 2: result.cellsRight = loadCellsLayout(sections[1])

proc updateContent(cell: var StatusBarCell, model: DataItemResolver) =
  cell.content.setLen 0
  for fragment in cell.contentFragments:
    case fragment[0]
    of ikStr, ikDollar:
      cell.content.add fragment[1]
    of ikExpr, ikVar:
      cell.content.add model(fragment[1])

proc updateCells(cells: var seq[StatusBarCell], model: DataItemResolver) =
  for cell in mitems(cells):
    cell.updateContent(model)

proc update*(s: var StatusBarView) =
  updateCells s.layout.cellsLeft, s.model
  updateCells s.layout.cellsRight, s.model

func width(cell: StatusBarCell): int =
  cell.label.len + cell.content.len + 4 # separator + pading

func width(cells: seq[StatusBarCell]): int =
  result = max(0, cells.len - 1) # the number of separators
  for cell in cells: result += cell.width

var complained = false
template ignoreException(body: untyped) =
  try:
    body
  except Exception as exc:
    if not complained:
      # TODO terminal.nim exception leak
      echo "Unable to update status bar: ", exc.msg
      complained = true

proc renderCells(cells: seq[StatusBarCell], sep: string) =
  for i, cell in cells:
    ignoreException:
      stdout.setBackgroundColor backgroundColor
      stdout.setForegroundColor foregroundColor
      stdout.setStyle {styleDim}
      if i > 0: stdout.write sep
      stdout.write " ", cell.label, ": "
      stdout.setStyle {styleBright}
      stdout.write cell.content, " "
      stdout.resetAttributes()

proc render*(s: var StatusBarView) {.raises: [Defect, ValueError].} =
  doAssert s.consumedLines == 0

  let
    termWidth = terminalWidth()
    allCellsWidth = s.layout.cellsLeft.width + s.layout.cellsRight.width

  if allCellsWidth > 0:
    ignoreException:
      renderCells(s.layout.cellsLeft, sepLeft)
      stdout.setBackgroundColor backgroundColor
      if termWidth > allCellsWidth:
        stdout.write spaces(termWidth - allCellsWidth)
        s.consumedLines = 1
      else:
        stdout.write spaces(max(0, termWidth - s.layout.cellsLeft.width)), "\p"
        s.consumedLines = 2
      renderCells(s.layout.cellsRight, sepRight)
      stdout.flushFile

proc erase*(s: var StatusBarView) =
  ignoreException:
    for i in 1 ..< s.consumedLines: cursorUp()
    for i in 0 ..< s.consumedLines: eraseLine()
    s.consumedLines = 0

func init*(T: type StatusBarView,
           layout: string,
           model: DataItemResolver): T {.raises: [Defect, ValueError].} =
  StatusBarView(model: model, consumedLines: 1, layout: loadLayout(layout))

