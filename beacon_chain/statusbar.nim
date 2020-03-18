import
  tables, strutils, parseutils, sequtils, terminal, colors

type
  ContentFragments = seq[tuple[kind: InterpolatedKind, value: string]]

  StatusBarCell = object
    label, content: string
    contentFragments: ContentFragments

  Layout = object
    cellsLeft: seq[StatusBarCell]
    cellsRight: seq[StatusBarCell]

  DataItemResolver* = proc (dataItem: string): string

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

func loadFragmentsLayout(contentLayout: string): ContentFragments =
  result = toSeq(interpolatedFragments(strip contentLayout))

func loadCellsLayout(cellsLayout: string): seq[StatusBarCell] =
  var cells = cellsLayout.split(';')
  for cell in cells:
    var columns = cell.split(':', maxSplit = 1)
    if columns.len == 2:
      result.add StatusBarCell(
        label: strip(columns[0]),
        contentFragments: loadFragmentsLayout(columns[1]))
    else:
      result.add StatusBarCell(
        contentFragments: loadFragmentsLayout(columns[0]))

func loadLayout(layout: string): Layout {.raises: [Defect, ValueError].} =
  var sections = layout.split('|', maxSplit = 1)
  result.cellsLeft = loadCellsLayout(sections[0])
  if sections.len == 2: result.cellsRight = loadCellsLayout(sections[1])

func updateContent(cell: var StatusBarCell, model: DataItemResolver) =
  cell.content.setLen 0
  for fragment in cell.contentFragments:
    case fragment[0]
    of ikStr, ikDollar:
      cell.content.add fragment[1]
    of ikExpr, ikVar:
      cell.content.add model(fragment[1])

func updateCells(cells: var seq[StatusBarCell], model: DataItemResolver) =
  for cell in mitems(cells):
    cell.updateContent(model)

func update*(s: var StatusBarView) =
  updateCells s.layout.cellsLeft, s.model
  updateCells s.layout.cellsRight, s.model

func width(cell: StatusBarCell): int =
  cell.label.len + cell.content.len + 4 # separator + pading

func width(cells: seq[StatusBarCell]): int =
  result = max(0, cells.len - 1) # the number of separators
  for cell in cells: result += cell.width

proc renderCells(cells: seq[StatusBarCell], sep: string) =
  for i, cell in cells:
    if i > 0: stdout.write sep
    stdout.setStyle {styleDim}
    stdout.write " ", cell.label, ": "
    stdout.setStyle {styleBright}
    stdout.write cell.content, " "

proc render*(s: var StatusBarView) =
  doAssert s.consumedLines == 0

  let
    termWidth = terminalWidth()
    allCellsWidth = s.layout.cellsLeft.width + s.layout.cellsRight.width

  if allCellsWidth > 0:
    stdout.setBackgroundColor backgroundColor
    stdout.setForegroundColor foregroundColor
    renderCells(s.layout.cellsLeft, sepLeft)
    if termWidth > allCellsWidth:
      stdout.write spaces(termWidth - allCellsWidth)
      s.consumedLines = 1
    else:
      stdout.write spaces(max(0, termWidth - s.layout.cellsLeft.width)), "\p"
      s.consumedLines = 2
    renderCells(s.layout.cellsRight, sepRight)
    stdout.resetAttributes
    stdout.flushFile

proc erase*(s: var StatusBarView) =
  for i in 1 ..< s.consumedLines: cursorUp()
  for i in 0 ..< s.consumedLines: eraseLine()
  s.consumedLines = 0

func init*(T: type StatusBarView,
           layout: string,
           model: DataItemResolver): T {.raises: [Defect, ValueError].} =
  StatusBarView(model: model, consumedLines: 1, layout: loadLayout(layout))

