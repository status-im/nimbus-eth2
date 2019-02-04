import
  sequtils, tables,
  spec/[datatypes, crypto, digest], ssz

type
  # TODO is it better to only key on some subset (e.g., shard+slot+beacon state hash)
  # of AttestationData? Using whole AttestationData does defend against some attacks.
  #
  # Per Danny as of 2018-12-21:
  # Yeah, you can do any linear combination of signatures. but you have to
  # remember the linear combination of pubkeys that constructed
  # if you have two instances of a signature from pubkey p, then you need 2*p
  # in the group pubkey because the attestation bitfield is only 1 bit per
  # pubkey right now, attestations do not support this it could be extended to
  # support N overlaps up to N times per pubkey if we had N bits per validator
  # instead of 1
  # We are shying away from this for the time being. If there end up being
  # substantial difficulties in network layer aggregation, then adding bits to
  # aid in supporting overlaps is one potential solution

  # TODO replace array[32, byte] with Eth2Digest from hash_tree_root_final from
  # https://github.com/status-im/nim-beacon-chain/pull/47

  # It would be better to combine these incrementally, pending above.
  AttestationPool* = object
    attestations: Table[uint64, Table[array[32, byte], seq[Attestation]]]

  # TODO priority queue or similar to track most-voted-on-AttestationData
  # per shard

proc init*(T: type AttestationPool): T =
  result.attestations = initTable[AttestationData, seq[Attestation]]()

func getLookupKey(attestationData: AttestationData): array[0..31, byte] =
  hash_tree_root(attestationData)

proc add*(pool: var AttestationPool,
          attestation: Attestation) =
  # Should be called for local and remote attestations.
  let key = getLookupKey(attestation.data)
  var attestations = pool.attestations.getOrDefault(attestation.data.shard).getOrDefault(key)

  # Basic sanity checks should already have been performed on this.
  # For example, if non-committee attestations shouldn't be included, this
  # doesn't separately check for that invariant.
  attestations.add(attestation)
  pool.attestations[attestation.data.shard][key] = attestations

func findMostCovering(pool: AttestationPool, shard: uint64): AttestationData =
  # Just a simple linear scan for now; could use various acceleration
  # data structures later, depending on tradeoff of how often queried
  # Might not be perf-sensitive; mostly per-epoch
  var mostAttestedData: AttestationData
  var maxLen: int = 0

  for perShardAttestations in values(pool.attestations[shard]):
    let l = perShardAttestations.len
    if l > maxLen:
      # Guaranteed to have at least one element if > 0
      mostAttestedData = perShardAttestations[0].data
      maxLen = l

  mostAttestedData

func getCombined(pool: AttestationPool, attestationData: AttestationData) : ValidatorSig =
  var signatures : seq[ValidatorSig] = @[]
  for perShardAttestation in pool.attestations.getOrDefault(attestationData.shard).getOrDefault(attestationData.getLookupKey):
    signatures.add(perShardAttestation.aggregate_signature)
  combine(signatures)

proc bitfieldUnion(accum: var seq[byte], disjunct: seq[byte]) =
  # TODO replace with nim-ranges
  doAssert len(accum) == len(disjunct)
  for i in 0 ..< len(accum):
    accum[i] = accum[i] or disjunct[i]

func getAggregatedAttestion*(pool: AttestationPool, shard: uint64) : Attestation =
  # TODO This might turn out to be a non-assertable condition, per, e.g.,
  # the recent discussion on error handling elsewhere in Nimbus, but it's
  # likelier that other code shouldn't be just randomly probing shards so
  # it's useful to start this way and catch logic errors early.
  assert shard in pool.attestations, "Attempt to query nonexistent shard"

  let mostCoveringAttestationData = findMostCovering(pool, shard)
  # TODO error handling where shard either doesn't exist or empty; needs
  # more holistic approach

  result.data = mostCoveringAttestationData

  let freqAttestations = pool.attestations[shard].getOrDefault(result.data.getLookupKey)
  # TODO probably this should not assert on failure

  # TODO Ugly, due to leaky seq[byte] non-abstraction. nim-ranges should help.
  result.participation_bitfield = repeat(0'u8, freqAttestations[0].participation_bitfield.len)
  for freqAttestation in freqAttestations:
    bitfieldUnion(result.participation_bitfield, freqAttestation.participation_bitfield)

  # TODO 2018-12-22 ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md
  # doesn't document semantics.
  # result.custody_bitfield = bitfieldUnion

  result.aggregate_signature = getCombined(pool, mostCoveringAttestationData)
