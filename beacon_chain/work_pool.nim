import
  tables,
  milagro_crypto,
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

  # TODO repeating array[32, byte] here isn't great
  # other approaches are possible/better

  # It would be better to combine these incrementally, pending above.
  # This back-loads the work.
  AttestationPool* = object
    attestations: Table[uint64, Table[array[32, byte], seq[Attestation]]]

  # TODO priority queue or similar to track most-voted-on-AttestationData
  # per shard

proc init*(T: type AttestationPool): T =
  result.attestations = initTable[AttestationData, seq[Attestation]]()

func getLookupKey(attestationData: AttestationData): array[0..31, byte] =
  hash_tree_root(attestationData)

proc addAttestation*(pool: var AttestationPool,
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

func getAggregatedAttestion*(pool: AttestationPool, shard: uint64) : Attestation =
  let mostCoveringAttestationData = findMostCovering(pool, shard)

  result.data = mostCoveringAttestationData

  # TODO: What's the best way to union participation_bitfield as seq[byte]?
  # Obvious methods, but a reusable abstraction probably exists.
  # result.participation_bitfield =
  # result.custody_bitfield =

  result.aggregate_signature = getCombined(pool, mostCoveringAttestationData)
