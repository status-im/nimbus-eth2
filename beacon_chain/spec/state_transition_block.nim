import ./datatypes/deneb

proc validate_blobs*(
    expected_kzg_commitments: seq[KzgCommitment], blobs: seq[KzgBlob],
    proofs: seq[KzgProof]): Result[void, string] =
  ok()
