import
  std/json,
  chronos,
  kzg4844/[kzg, kzg_abi],
  taskpools,
  ./beacon_chain/spec/datatypes/fulu,
  ./tests/consensus_spec/os_ops

from std/cmdline import commandLineParams
from std/strutils import parseInt, rsplit
from stew/byteutils import fromHex
from ./beacon_chain/spec/peerdas_helpers import
  recover_matrix, recover_cells_and_proofs_parallel

func fromHex[N: static int](s: string): Opt[array[N, byte]] =
  if s.len != 2*(N+1):
    # 0x prefix
    return Opt.none array[N, byte]

  try:
    Opt.some fromHex(array[N, byte], s)
  except ValueError:
    Opt.none array[N, byte]

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert loadTrustedSetup(
    sourceDir &
      "/vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 0).isOk

const rowCount = 1
block:
  let f = commandLineParams()[0]
  let columns = parseJson(os_ops.readFile(f))["data"]
  let colCount = columns.len
  echo colCount
  doAssert colCount == 128
  const usedColumns = 128
  var colInput = newSeq[ref fulu.DataColumnSidecar](usedColumns)
  var tp = Taskpool.new(numThreads = 1)
  var matrixentries: seq[MatrixEntry]

  for columnpair in columns:
    let
      index = columnpair["index"].getStr.parseInt
      column = columnpair["column"]

    if index >= usedColumns: continue
    doAssert column.len == 21

    # for parallel
    var cells = newSeq[Cell](rowCount)
    for j in 0 ..< rowCount:
      cells[j] = KzgCell(bytes: fromHex[2048](column[j].getStr).get)
    colInput[index] = (ref fulu.DataColumnSidecar)(
      index: index.ColumnIndex,
      column: DataColumn(cells))

    for k in 0..<cells.len:
      matrixentries.add(MatrixEntry(cell: cells[k], row_index: k.RowIndex, column_index: index.ColumnIndex))

  block:
    let x = Moment.now()
    let v = tp.recover_cells_and_proofs_parallel(colInput)
    echo Moment.now() - x
    doAssert v.isOk

  block:
    let x = Moment.now()
    let v = recover_matrix(matrixentries, rowCount)
    doAssert v.isOk
    echo Moment.now() - x