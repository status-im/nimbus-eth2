# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## Local file of the trees of the PQ keys of local validators.
##
## A node signs with the trees it has hashed: the top tree and a few bottom
## trees of each XMSS key, and the subtree roots of each VRF tree. Hashing
## them takes seconds per key, minutes for hundreds of keys, during which the
## validators do no duties. The trees are therefore written to a file once
## hashed, and read from it when the node starts again.
##
## The file holds no secret. A record is the trees of one validator, followed
## by its digest: a record that is damaged ends the reading of the file, and
## the trees of the validators without a record are hashed as before. The XMSS
## trees are checked against the XMSS public key when they are loaded, and the
## VRF tree against the VRF root of the validator when its state is.

import
  std/os,
  results,
  stew/endians2,
  nimcrypto/[hash, sha2],
  ../spec/[crypto, digest, pq_vrf, xmss]

export results, crypto, xmss

const
  PqTreeCacheName* = "pq_tree_cache.bin"

  XMSS_MAX_CACHED_BOTTOM_TREES* = 4
    ## The number of bottom trees an XMSS key keeps, those it used last
  XMSS_MAX_TREE_CACHE_SIZE* =
    XMSS_CACHED_TOP_TREE_SIZE +
      XMSS_MAX_CACHED_BOTTOM_TREES * XMSS_CACHED_BOTTOM_TREE_SIZE

  magic = "NPQTREE1"
  pubkeySize = sizeof(ValidatorPubKey().blob)
  headerSize = pubkeySize + XMSS_PUBKEY_SIZE + 2 * sizeof(uint32)
  digestSize = sizeof(Eth2Digest().data)

proc c_rename(oldPath, newPath: cstring): cint {.
  importc: "rename", header: "<stdio.h>".}

type
  PqTreeCacheRecord* = object
    ## The trees of the PQ keys of the validator with BLS key ``pubkey``
    pubkey*: ValidatorPubKey
    xmssPubkey*: XMSSPubkey
    xmssTrees*: seq[byte]
      ## `treeCache` of the XMSS key
    vrfSubtreeRoots*: seq[byte]
      ## `subtreeRoots` of the VRF tree; empty when not known

  PqTreeCacheWriter* = object
    file: File
    path, tmpPath: string
    records*: int

func isXmssTreeCacheLen(len: int): bool =
  len >= XMSS_CACHED_TOP_TREE_SIZE and len <= XMSS_MAX_TREE_CACHE_SIZE and
    (len - XMSS_CACHED_TOP_TREE_SIZE) mod XMSS_CACHED_BOTTOM_TREE_SIZE == 0

func isVrfSubtreeRootsLen(len: int): bool =
  len == 0 or len == VRF_SUBTREE_ROOTS_SIZE

func xmssBottomTrees*(xmssTrees: openArray[byte]): seq[uint32] =
  ## The indices of the bottom trees in the `treeCache` of an XMSS key, in the
  ## order of the cache.
  var res: seq[uint32]
  if not isXmssTreeCacheLen(xmssTrees.len):
    return res
  var at = XMSS_CACHED_TOP_TREE_SIZE
  while at < xmssTrees.len:
    res.add uint32.fromBytesLE(xmssTrees.toOpenArray(at, at + 3))
    at += XMSS_CACHED_BOTTOM_TREE_SIZE
  res

func encodeHeader(record: PqTreeCacheRecord): array[headerSize, byte] =
  var res: array[headerSize, byte]
  res[0 ..< pubkeySize] = record.pubkey.blob
  res[pubkeySize ..< pubkeySize + XMSS_PUBKEY_SIZE] = record.xmssPubkey.blob
  res[headerSize - 8 ..< headerSize - 4] =
    uint32(record.xmssTrees.len).toBytesLE()
  res[headerSize - 4 ..< headerSize] =
    uint32(record.vrfSubtreeRoots.len).toBytesLE()
  res

func digest(header: openArray[byte], record: PqTreeCacheRecord): Eth2Digest =
  withEth2Hash:
    h.update(header)
    h.update(record.xmssTrees)
    h.update(record.vrfSubtreeRoots)

proc readExact(file: File, len: int): Opt[seq[byte]] =
  var res = newSeq[byte](len)
  if len > 0:
    try:
      if file.readBytes(res, 0, len) != len:
        return Opt.none(seq[byte])
    except IOError:
      return Opt.none(seq[byte])
  Opt.some res

proc readRecord(file: File): Opt[PqTreeCacheRecord] =
  let
    header = ? file.readExact(headerSize)
    xmssLen = int(uint32.fromBytesLE(
      header.toOpenArray(headerSize - 8, headerSize - 5)))
    vrfLen = int(uint32.fromBytesLE(
      header.toOpenArray(headerSize - 4, headerSize - 1)))
  if not isXmssTreeCacheLen(xmssLen) or not isVrfSubtreeRootsLen(vrfLen):
    return Opt.none(PqTreeCacheRecord)
  var record = PqTreeCacheRecord(
    xmssTrees: ? file.readExact(xmssLen),
    vrfSubtreeRoots: ? file.readExact(vrfLen))
  record.pubkey.blob[0 ..< pubkeySize] =
    header.toOpenArray(0, pubkeySize - 1)
  record.xmssPubkey.blob[0 ..< XMSS_PUBKEY_SIZE] =
    header.toOpenArray(pubkeySize, pubkeySize + XMSS_PUBKEY_SIZE - 1)
  let stored = ? file.readExact(digestSize)
  if stored != @(digest(header, record).data):
    return Opt.none(PqTreeCacheRecord)
  Opt.some record

proc readPqTreeCache*(path: string): seq[PqTreeCacheRecord] =
  ## The records of the file at ``path``, up to the first one that is damaged
  ## or cut short; none when there is no such file.
  var
    res: seq[PqTreeCacheRecord]
    file: File
  if not open(file, path, fmRead):
    return res
  defer: file.close()
  let found = file.readExact(magic.len).valueOr:
    return res
  if found != @(magic.toOpenArrayByte(0, magic.high)):
    return res
  while true:
    let record = file.readRecord().valueOr:
      break
    res.add record
  res

proc init*(T: type PqTreeCacheWriter, path: string): Result[T, string] =
  ## Start writing the file at ``path``, which is replaced when the writer
  ## finishes: until then, and if it does not, the file is left as it is.
  var writer = T(path: path, tmpPath: path & ".tmp")
  if not open(writer.file, writer.tmpPath, fmWrite):
    return err("cannot create " & writer.tmpPath)
  try:
    writer.file.write(magic)
  except IOError as exc:
    writer.file.close()
    return err(exc.msg)
  ok writer

proc add*(
    writer: var PqTreeCacheWriter,
    record: PqTreeCacheRecord): Result[void, string] =
  if not isXmssTreeCacheLen(record.xmssTrees.len) or
      not isVrfSubtreeRootsLen(record.vrfSubtreeRoots.len):
    return err("trees of unexpected size")
  let
    header = record.encodeHeader()
    digest = digest(header, record)
  template put(data: untyped): bool =
    data.len == 0 or writer.file.writeBytes(data, 0, data.len) == data.len
  try:
    if not (put(header) and put(record.xmssTrees) and
        put(record.vrfSubtreeRoots) and put(digest.data)):
      return err("cannot write to " & writer.tmpPath)
  except IOError as exc:
    return err(exc.msg)
  inc writer.records
  ok()

proc abandon*(writer: var PqTreeCacheWriter) =
  ## Stop writing and leave the file as it was.
  if not writer.file.isNil:
    writer.file.close()
    writer.file = nil
    discard tryRemoveFile(writer.tmpPath)

proc finish*(writer: var PqTreeCacheWriter): Result[void, string] =
  ## Replace the file with what was written.
  if writer.file.isNil:
    return err("writer is closed")
  try:
    writer.file.flushFile()
  except IOError as exc:
    writer.abandon()
    return err(exc.msg)
  writer.file.close()
  writer.file = nil
  if c_rename(cstring(writer.tmpPath), cstring(writer.path)) != 0:
    # Where a file is not renamed onto another, the old one goes first
    discard tryRemoveFile(writer.path)
    if c_rename(cstring(writer.tmpPath), cstring(writer.path)) != 0:
      discard tryRemoveFile(writer.tmpPath)
      return err("cannot rename " & writer.tmpPath)
  ok()
