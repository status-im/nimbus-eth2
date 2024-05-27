# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec

import
  algorithm,
  std/macros,
  results,
  stew/assign2,
  chronicles,
  std/sequtils,
  ./[beacon_time, crypto],
  eth/p2p/discoveryv5/[node],
  ./helpers,
  ./datatypes/[eip7594]


#### `cell_to_coset_evals`


# proc cell_to_coset_evals(cell: Cell): CosetEvals =
#     discard """
#     Convert an untrusted ``Cell`` into a trusted ``CosetEvals``.
#     """
#     # evals = []
#     # for i in range(FIELD_ELEMENTS_PER_CELL):
#     #     start = i * BYTES_PER_FIELD_ELEMENT
#     #     end = (i + 1) * BYTES_PER_FIELD_ELEMENT
#     #     value = bytes_to_bls_field(cell[start:end])
#     #     evals.append(value)
#     # return CosetEvals(evals)


# #### `coset_evals_to_cell`


# proc coset_evals_to_cell(coset_evals: CosetEvals): Cell =
#     discard """
#     Convert a trusted ``CosetEval`` into an untrusted ``Cell``.
#     """
#     # cell = []
#     # for i in range(FIELD_ELEMENTS_PER_CELL):
#     #     cell += bls_field_to_bytes(coset_evals[i])
#     # return Cell(cell)


# ### Linear combinations

# #### `g2_lincomb`


# proc g2_lincomb(points: openArray[G2Point], scalars: seq[BLSFieldElement]): Bytes96 =
#     discard """
#     BLS multiscalar multiplication in G2. This can be naively implemented using double-and-add.
#     """
#     # assert len(points) == len(scalars)

#     # if len(points) == 0:
#     #     return bls.G2_to_bytes96(bls.Z2())

#     # points_g2 = []
#     # for point in points:
#     #     points_g2.append(bls.bytes96_to_G2(point))

#     # result = bls.multi_exp(points_g2, scalars)
#     # return Bytes96(bls.G2_to_bytes96(result))


# ### FFTs

# #### `_fft_field`


# proc xfft_field(vals: openArray[BLSFieldElement],
#                roots_of_unity: openArray[BLSFieldElement]): seq[BLSFieldElement] =
#     # if len(vals) == 1:
#     #     return vals
#     # L = _fft_field(vals[::2], roots_of_unity[::2])
#     # R = _fft_field(vals[1::2], roots_of_unity[::2])
#     # o = [BLSFieldElement(0) for _ in vals]
#     # for i, (x, y) in enumerate(zip(L, R)):
#     #     y_times_root = (int(y) * int(roots_of_unity[i])) % BLS_MODULUS
#     #     o[i] = BLSFieldElement((int(x) + y_times_root) % BLS_MODULUS)
#     #     o[i + len(L)] = BLSFieldElement((int(x) - y_times_root + BLS_MODULUS) % BLS_MODULUS)
#     # return o
#     discard

# #### `fft_field`


# proc fft_field(vals: openArray[BLSFieldElement],
#               roots_of_unity: openArray[BLSFieldElement],
#               inv: bool=false): openArray[BLSFieldElement] =
#     # if inv:
#     #     # Inverse FFT
#     #     invlen = pow(len(vals), BLS_MODULUS - 2, BLS_MODULUS)
#     #     return [BLSFieldElement((int(x) * invlen) % BLS_MODULUS)
#     #             for x in xfft_field(vals, list(roots_of_unity[0:1]) + list(roots_of_unity[:0:-1]))]
#     # else:
#     #     # Regular FFT
#     #     return xfft_field(vals, roots_of_unity)
#     discard


# ### Polynomials in coefficient form

# #### `polynomial_eval_to_coeff`


# proc polynomial_eval_to_coeff(polynomial: Polynomial): PolynomialCoeff =
    
#     discard """
#     Interpolates a polynomial (given in evaluation form) to a polynomial in coefficient form.
#     """
#     # let roots_of_unity = compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
#     # let polynomial_coeff = fft_field(bit_reversal_permutation(list(polynomial)), roots_of_unity, inv=True)

#     # return polynomial_coeff

#     discard
# #### `add_polynomialcoeff`


# proc add_polynomialcoeff(a: PolynomialCoeff, b: PolynomialCoeff): PolynomialCoeff =
#     discard """
#     Sum the coefficient form polynomials ``a`` and ``b``.
#     """
#     # a, b = (a, b) if len(a) >= len(b) else (b, a)
#     # length_a = len(a)
#     # length_b = len(b)
#     # return [(a[i] + (b[i] if i < length_b else 0)) % BLS_MODULUS for i in range(length_a)]

#     discard
# #### `neg_polynomialcoeff`


# proc neg_polynomialcoeff(a: PolynomialCoeff): PolynomialCoeff =
#     discard """
#     Negative of coefficient form polynomial ``a``
#     """
#     # return [(BLS_MODULUS - x) % BLS_MODULUS for x in a]

#     discard
# #### `multiply_polynomialcoeff`


# proc multiply_polynomialcoeff(a: PolynomialCoeff, b: PolynomialCoeff): PolynomialCoeff =
#     discard """
#     Multiplies the coefficient form polynomials ``a`` and ``b``
#     """
#     # assert len(a) + len(b) <= FIELD_ELEMENTS_PER_EXT_BLOB

#     # r = [0]
#     # for power, coef in enumerate(a):
#     #     summand = [0] * power + [int(coef) * int(x) % BLS_MODULUS for x in b]
#     #     r = add_polynomialcoeff(r, summand)
#     # return r

#     discard
# #### `divide_polynomialcoeff`


# proc divide_polynomialcoeff(a: PolynomialCoeff, b: PolynomialCoeff): PolynomialCoeff =
#     discard """
#     Long polynomial division for two coefficient form polynomials ``a`` and ``b``
#     """
#     # a = a.copy()  # Make a copy since `a` is passed by reference
#     # o: List[BLSFieldElement] = []
#     # apos = len(a) - 1
#     # bpos = len(b) - 1
#     # diff = apos - bpos
#     # while diff >= 0:
#     #     quot = div(a[apos], b[bpos])
#     #     o.insert(0, quot)
#     #     for i in range(bpos, -1, -1):
#     #         a[diff + i] = (int(a[diff + i]) - int(b[i] + BLS_MODULUS) * int(quot)) % BLS_MODULUS
#     #     apos -= 1
#     #     diff -= 1
#     # return [x % BLS_MODULUS for x in o]

#     discard
# #### `shift_polynomialcoeff`


# proc shift_polynomialcoeff(polynomial_coeff: PolynomialCoeff, factor: BLSFieldElement): PolynomialCoeff =
#     discard """
#     Shift the evaluation of a polynomial in coefficient form by factor.
#     This results in a new polynomial g(x) = f(factor * x)
#     """
#     # factor_power = 1
#     # inv_factor = pow(int(factor), BLS_MODULUS - 2, BLS_MODULUS)
#     # o = []
#     # for p in polynomial_coeff:
#     #     o.append(int(p) * factor_power % BLS_MODULUS)
#     #     factor_power = factor_power * inv_factor % BLS_MODULUS
#     # return o

#     discard
# #### `interpolate_polynomialcoeff`


# proc interpolate_polynomialcoeff(xs: openArray[BLSFieldElement], ys: openArray[BLSFieldElement]): PolynomialCoeff =
#     discard """
#     Lagrange interpolation: Finds the lowest degree polynomial that takes the value ``ys[i]`` at ``x[i]``
#     for all i.
#     Outputs a coefficient form polynomial. Leading coefficients may be zero.
#     """
#     # assert len(xs) == len(ys)
#     # r = [0]

#     # for i in range(len(xs)):
#     #     summand = [ys[i]]
#     #     for j in range(len(ys)):
#     #         if j != i:
#     #             weight_adjustment = bls_modular_inverse(int(xs[i]) - int(xs[j]))
#     #             summand = multiply_polynomialcoeff(
#     #                 summand, [((BLS_MODULUS - int(weight_adjustment)) * int(xs[j])) % BLS_MODULUS, weight_adjustment]
#     #             )
#     #     r = add_polynomialcoeff(r, summand)

#     # return r

#     discard
# #### `vanishing_polynomialcoeff`


# proc vanishing_polynomialcoeff(xs: openArray[BLSFieldElement]): PolynomialCoeff =
#     discard """
#     Compute the vanishing polynomial on ``xs`` (in coefficient form)
#     """
#     # p = [1]
#     # for x in xs:
#     #     p = multiply_polynomialcoeff(p, [-int(x) + BLS_MODULUS, 1])
#     # return p

#     discard
# #### `evaluate_polynomialcoeff`


# proc evaluate_polynomialcoeff(polynomial_coeff: PolynomialCoeff, z: BLSFieldElement): BLSFieldElement =
#     discard """
#     Evaluate a coefficient form polynomial at ``z`` using Horner's schema
#     """
#     # y = 0
#     # for coef in polynomial_coeff[::-1]:
#     #     y = (int(y) * int(z) + int(coef)) % BLS_MODULUS
#     # return BLSFieldElement(y % BLS_MODULUS)

#     discard
# ### KZG multiproofs

# # Extended KZG functions for multiproofs

# #### `compute_kzg_proof_multi_impl`


# proc compute_kzg_proof_multi_impl(
#         polynomial_coeff: PolynomialCoeff,
#         zs: Coset): (KzgProof, CosetEvals) =
#     discard """
#     Compute a KZG multi-evaluation proof for a set of `k` points.

#     This is done by committing to the following quotient polynomial:
#         Q(X) = f(X) - I(X) / Z(X)
#     Where:
#         - I(X) is the degree `k-1` polynomial that agrees with f(x) at all `k` points
#         - Z(X) is the degree `k` polynomial that evaluates to zero on all `k` points

#     We further note that since the degree of I(X) is less than the degree of Z(X),
#     the computation can be simplified in monomial form to Q(X) = f(X) / Z(X)
#     """

#     # # For all points, compute the evaluation of those points
#     # ys = [evaluate_polynomialcoeff(polynomial_coeff, z) for z in zs]

#     # # Compute Z(X)
#     # denominator_poly = vanishing_polynomialcoeff(zs)

#     # # Compute the quotient polynomial directly in monomial form
#     # quotient_polynomial = divide_polynomialcoeff(polynomial_coeff, denominator_poly)

#     # return KZGProof(g1_lincomb(KZG_SETUP_G1_MONOMIAL[:len(quotient_polynomial)], quotient_polynomial)), ys

#     discard
# #### `verify_kzg_proof_multi_impl`


# proc verify_kzg_proof_multi_impl(commitment: KzgCommitment,
#                                 zs: Coset,
#                                 ys: CosetEvals,
#                                 proof: KZGProof): bool =
#     discard """
#     Verify a KZG multi-evaluation proof for a set of `k` points.

#     This is done by checking if the following equation holds:
#         Q(x) Z(x) = f(X) - I(X)
#     Where:
#         f(X) is the polynomial that we want to verify opens at `k` points to `k` values
#         Q(X) is the quotient polynomial computed by the prover
#         I(X) is the degree k-1 polynomial that evaluates to `ys` at all `zs`` points
#         Z(X) is the polynomial that evaluates to zero on all `k` points

#     The verifier receives the commitments to Q(X) and f(X), so they check the equation
#     holds by using the following pairing equation:
#         e([Q(X)]_1, [Z(X)]_2) == e([f(X)]_1 - [I(X)]_1, [1]_2)
#     """

#     # assert len(zs) == len(ys)

#     # # Compute [Z(X)]_2
#     # zero_poly = g2_lincomb(KZG_SETUP_G2_MONOMIAL[:len(zs) + 1], vanishing_polynomialcoeff(zs))
#     # # Compute [I(X)]_1
#     # interpolated_poly = g1_lincomb(KZG_SETUP_G1_MONOMIAL[:len(zs)], interpolate_polynomialcoeff(zs, ys))

#     # return (bls.pairing_check([
#     #     [bls.bytes48_to_G1(proof), bls.bytes96_to_G2(zero_poly)],
#     #     [
#     #         bls.add(bls.bytes48_to_G1(commitment), bls.neg(bls.bytes48_to_G1(interpolated_poly))),
#     #         bls.neg(bls.bytes96_to_G2(KZG_SETUP_G2_MONOMIAL[0])),
#     #     ],
#     # ]))


# ### Cell cosets

# #### `coset_for_cell`


# proc coset_for_cell(cell_id: CellID): Coset =
#     discard """
#     Get the coset for a given ``cell_id``
#     """
#     # assert cell_id < CELLS_PER_EXT_BLOB
#     # roots_of_unity_brp = bit_reversal_permutation(
#     #     compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB)
#     # )
#     # return Coset(roots_of_unity_brp[FIELD_ELEMENTS_PER_CELL * cell_id:FIELD_ELEMENTS_PER_CELL * (cell_id + 1)])


# ## Cells

# ### Cell computation

# #### `compute_cells_and_kzg_proofs`


# proc compute_cells_and_kzg_proofs(blob: Blob): Tuple[
#         Vector[Cell, CELLS_PER_EXT_BLOB],
#         Vector[KZGProof, CELLS_PER_EXT_BLOB]] =
#     discard """
#     Compute all the cell proofs for an extended blob. This is an inefficient O(n^2) algorithm,
#     for performant implementation the FK20 algorithm that runs in O(n log n) should be
#     used instead.

#     Public method.
#     """
#     # assert len(blob) == BYTES_PER_BLOB

#     # polynomial = blob_to_polynomial(blob)
#     # polynomial_coeff = polynomial_eval_to_coeff(polynomial)

#     # cells = []
#     # proofs = []

#     # for i in range(CELLS_PER_EXT_BLOB):
#     #     coset = coset_for_cell(CellID(i))
#     #     proof, ys = compute_kzg_proof_multi_impl(polynomial_coeff, coset)
#     #     cells.append(coset_evals_to_cell(ys))
#     #     proofs.append(proof)

#     # return cells, proofs


# #### `compute_cells`


# proc compute_cells(blob: Blob): array[CELLS_PER_EXT_BLOB, Cell]:
#     discard """
#     Compute the cell data for an extended blob (without computing the proofs).

#     Public method.
#     """
#     # assert len(blob) == BYTES_PER_BLOB

#     # polynomial = blob_to_polynomial(blob)
#     # polynomial_coeff = polynomial_eval_to_coeff(polynomial)

#     # extended_data = fft_field(polynomial_coeff + [0] * FIELD_ELEMENTS_PER_BLOB,
#     #                           compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB))
#     # extended_data_rbo = bit_reversal_permutation(extended_data)
#     # cells = []
#     # for cell_id in range(CELLS_PER_EXT_BLOB):
#     #     start = cell_id * FIELD_ELEMENTS_PER_CELL
#     #     end = (cell_id + 1) * FIELD_ELEMENTS_PER_CELL
#     #     cells.append(coset_evals_to_cell(CosetEvals(extended_data_rbo[start:end])))
#     # return cells


# ### Cell verification

# #### `verify_cell_kzg_proof`


# proc verify_cell_kzg_proof(commitment_bytes: Bytes48,
#                           cell_id: CellID,
#                           cell: Cell,
#                           proof_bytes: Bytes48): bool =
#     discard """
#     Check a cell proof

#     Public method.
#     """
#     # assert len(commitment_bytes) == BYTES_PER_COMMITMENT
#     # assert cell_id < CELLS_PER_EXT_BLOB
#     # assert len(cell) == BYTES_PER_CELL
#     # assert len(proof_bytes) == BYTES_PER_PROOF

#     # coset = coset_for_cell(cell_id)

#     # return verify_kzg_proof_multi_impl(
#     #     bytes_to_kzg_commitment(commitment_bytes),
#     #     coset,
#     #     cell_to_coset_evals(cell),
#     #     bytes_to_kzg_proof(proof_bytes))


# #### `verify_cell_kzg_proof_batch`


# proc verify_cell_kzg_proof_batch(row_commitments_bytes: openArray[Bytes48],
#                                 row_indices: openArray[RowIndex],
#                                 column_indices: openArray[ColumnIndex],
#                                 cells: openArray[Cell],
#                                 proofs_bytes: openArray[Bytes48]): bool =
#     discard """
#     Verify a set of cells, given their corresponding proofs and their coordinates (row_id, column_id) in the blob
#     matrix. The list of all commitments is also provided in row_commitments_bytes.

#     This function implements the naive algorithm of checking every cell
#     individually; an efficient algorithm can be found here:
#     https://ethresear.ch/t/a-universal-verification-equation-for-data-availability-sampling/13240

#     This implementation does not require randomness, but for the algorithm that
#     requires it, `RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN` should be used to compute
#     the challenge value.

#     Public method.
#     """
#     # assert len(cells) == len(proofs_bytes) == len(row_indices) == len(column_indices)
#     # for commitment_bytes in row_commitments_bytes:
#     #     assert len(commitment_bytes) == BYTES_PER_COMMITMENT
#     # for row_index in row_indices:
#     #     assert row_index < len(row_commitments_bytes)
#     # for column_index in column_indices:
#     #     assert column_index < CELLS_PER_EXT_BLOB
#     # for cell in cells:
#     #     assert len(cell) == BYTES_PER_CELL
#     # for proof_bytes in proofs_bytes:
#     #     assert len(proof_bytes) == BYTES_PER_PROOF

#     # # Get commitments via row IDs
#     # commitments_bytes = [row_commitments_bytes[row_index] for row_index in row_indices]

#     # # Get objects from bytes
#     # commitments = [bytes_to_kzg_commitment(commitment_bytes) for commitment_bytes in commitments_bytes]
#     # cosets_evals = [cell_to_coset_evals(cell) for cell in cells]
#     # proofs = [bytes_to_kzg_proof(proof_bytes) for proof_bytes in proofs_bytes]

#     # return all(
#     #     verify_kzg_proof_multi_impl(commitment, coset_for_cell(column_index), coset_evals, proof)
#     #     for commitment, column_index, coset_evals, proof in zip(commitments, column_indices, cosets_evals, proofs)
#     # )


# ## Reconstruction

# ### `construct_vanishing_polynomial`


# proc construct_vanishing_polynomial(missing_cell_ids: openArray[CellID]) -> tuple[
#         seq[BLSFieldElement],
#         seq[BLSFieldElement]]:
#     discard """
#     Given the cells that are missing from the data, compute the polynomial that vanishes at every point that
#     corresponds to a missing field element.
#     """
#     # # Get the small domain
#     # roots_of_unity_reduced = compute_roots_of_unity(CELLS_PER_EXT_BLOB)

#     # # Compute polynomial that vanishes at all the missing cells (over the small domain)
#     # short_zero_poly = vanishing_polynomialcoeff([
#     #     roots_of_unity_reduced[reverse_bits(missing_cell_id, CELLS_PER_EXT_BLOB)]
#     #     for missing_cell_id in missing_cell_ids
#     # ])

#     # # Extend vanishing polynomial to full domain using the closed form of the vanishing polynomial over a coset
#     # zero_poly_coeff = [BLSFieldElement(0)] * FIELD_ELEMENTS_PER_EXT_BLOB
#     # for i, coeff in enumerate(short_zero_poly):
#     #     zero_poly_coeff[i * FIELD_ELEMENTS_PER_CELL] = coeff

#     # # Compute evaluations of the extended vanishing polynomial
#     # zero_poly_eval = fft_field(zero_poly_coeff,
#     #                            compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB))
#     # zero_poly_eval_brp = bit_reversal_permutation(zero_poly_eval)

#     # # Sanity check
#     # for cell_id in range(CELLS_PER_EXT_BLOB):
#     #     start = cell_id * FIELD_ELEMENTS_PER_CELL
#     #     end = (cell_id + 1) * FIELD_ELEMENTS_PER_CELL
#     #     if cell_id in missing_cell_ids:
#     #         assert all(a == 0 for a in zero_poly_eval_brp[start:end])
#     #     else:  # cell_id in cell_ids
#     #         assert all(a != 0 for a in zero_poly_eval_brp[start:end])

#     # return zero_poly_coeff, zero_poly_eval


# ### `recover_shifted_data`


# proc recover_shifted_data(cell_ids: openArray[CellID],
#                          cells: openArray[Cell],
#                          zero_poly_eval: openArray[BLSFieldElement],
#                          zero_poly_coeff: openArray[BLSFieldElement],
#                          roots_of_unity_extended: openArray[BLSFieldElement]): tuple[
#                              seq[BLSFieldElement],
#                              seq[BLSFieldElement],
#                              BLSFieldElement] =
#     discard """
#     Given Z(x), return polynomial Q_1(x)=(E*Z)(k*x) and Q_2(x)=Z(k*x) and k^{-1}.
#     """
#     # shift_factor = BLSFieldElement(PRIMITIVE_ROOT_OF_UNITY)
#     # shift_inv = div(BLSFieldElement(1), shift_factor)

#     # extended_evaluation_rbo = [0] * FIELD_ELEMENTS_PER_EXT_BLOB
#     # for cell_id, cell in zip(cell_ids, cells):
#     #     start = cell_id * FIELD_ELEMENTS_PER_CELL
#     #     end = (cell_id + 1) * FIELD_ELEMENTS_PER_CELL
#     #     extended_evaluation_rbo[start:end] = cell
#     # extended_evaluation = bit_reversal_permutation(extended_evaluation_rbo)

#     # # Compute (E*Z)(x)
#     # extended_evaluation_times_zero = [BLSFieldElement(int(a) * int(b) % BLS_MODULUS)
#     #                                   for a, b in zip(zero_poly_eval, extended_evaluation)]

#     # extended_evaluations_fft = fft_field(extended_evaluation_times_zero, roots_of_unity_extended, inv=True)

#     # # Compute (E*Z)(k*x)
#     # shifted_extended_evaluation = shift_polynomialcoeff(extended_evaluations_fft, shift_factor)
#     # # Compute Z(k*x)
#     # shifted_zero_poly = shift_polynomialcoeff(zero_poly_coeff, shift_factor)

#     # eval_shifted_extended_evaluation = fft_field(shifted_extended_evaluation, roots_of_unity_extended)
#     # eval_shifted_zero_poly = fft_field(shifted_zero_poly, roots_of_unity_extended)

#     # return eval_shifted_extended_evaluation, eval_shifted_zero_poly, shift_inv


# ### `recover_original_data`


# proc recover_original_data(eval_shifted_extended_evaluation: openArray[BLSFieldElement],
#                           eval_shifted_zero_poly: openArray[BLSFieldElement],
#                           shift_inv: BLSFieldElement,
#                           roots_of_unity_extended: openArray[BLSFieldElement]): seq[BLSFieldElement] =
#     discard """
#     Given Q_1, Q_2 and k^{-1}, compute P(x).
#     """
#     # # Compute Q_3 = Q_1(x)/Q_2(x) = P(k*x)
#     # eval_shifted_reconstructed_poly = [
#     #     div(a, b)
#     #     for a, b in zip(eval_shifted_extended_evaluation, eval_shifted_zero_poly)
#     # ]

#     # shifted_reconstructed_poly = fft_field(eval_shifted_reconstructed_poly, roots_of_unity_extended, inv=True)

#     # # Unshift P(k*x) by k^{-1} to get P(x)
#     # reconstructed_poly = shift_polynomialcoeff(shifted_reconstructed_poly, shift_inv)

#     # reconstructed_data = bit_reversal_permutation(fft_field(reconstructed_poly, roots_of_unity_extended))

#     # return reconstructed_data


# ### `recover_all_cells`


# proc recover_all_cells(cell_ids: openArray[CellID], cells: openArray[Cell]): openArray[Cell] =
#     discard """
#     Recover all of the cells in the extended blob from FIELD_ELEMENTS_PER_EXT_BLOB evaluations,
#     half of which can be missing.
#     This algorithm uses FFTs to recover cells faster than using Lagrange implementation, as can be seen here:
#     https://ethresear.ch/t/reed-solomon-erasure-code-recovery-in-n-log-2-n-time-with-ffts/3039

#     A faster version thanks to Qi Zhou can be found here:
#     https://github.com/ethereum/research/blob/51b530a53bd4147d123ab3e390a9d08605c2cdb8/polynomial_reconstruction/polynomial_reconstruction_danksharding.py

#     Public method.
#     """
#     # assert len(cell_ids) == len(cells)
#     # # Check we have enough cells to be able to perform the reconstruction
#     # assert CELLS_PER_EXT_BLOB / 2 <= len(cell_ids) <= CELLS_PER_EXT_BLOB
#     # # Check for duplicates
#     # assert len(cell_ids) == len(set(cell_ids))
#     # # Check that each cell is the correct length
#     # for cell in cells:
#     #     assert len(cell) == BYTES_PER_CELL

#     # # Get the extended domain
#     # roots_of_unity_extended = compute_roots_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB)

#     # # Convert cells to coset evals
#     # cosets_evals = [cell_to_coset_evals(cell) for cell in cells]

#     # missing_cell_ids = [CellID(cell_id) for cell_id in range(CELLS_PER_EXT_BLOB) if cell_id not in cell_ids]
#     # zero_poly_coeff, zero_poly_eval = construct_vanishing_polynomial(missing_cell_ids)

#     # eval_shifted_extended_evaluation, eval_shifted_zero_poly, shift_inv = recover_shifted_data(
#     #     cell_ids,
#     #     cosets_evals,
#     #     zero_poly_eval,
#     #     zero_poly_coeff,
#     #     roots_of_unity_extended,
#     # )

#     # reconstructed_data = recover_original_data(
#     #     eval_shifted_extended_evaluation,
#     #     eval_shifted_zero_poly,
#     #     shift_inv,
#     #     roots_of_unity_extended,
#     # )

#     # for cell_id, coset_evals in zip(cell_ids, cosets_evals):
#     #     start = cell_id * FIELD_ELEMENTS_PER_CELL
#     #     end = (cell_id + 1) * FIELD_ELEMENTS_PER_CELL
#     #     assert reconstructed_data[start:end] == coset_evals

#     # reconstructed_data_as_cells = [
#     #     coset_evals_to_cell(reconstructed_data[i * FIELD_ELEMENTS_PER_CELL:(i + 1) * FIELD_ELEMENTS_PER_CELL])
#     #     for i in range(CELLS_PER_EXT_BLOB)]

#     # return reconstructed_data_as_cells



# #### `get_custody_columns`

proc sortedColumnIndices*(columnsPerSubnet: ColumnIndex, subnetIds: HashSet[uint64]): seq[ColumnIndex] =
  var res: seq[ColumnIndex] = @[]
  for i in 0 ..< columnsPerSubnet:
    for subnetId in subnetIds:
      let index = DATA_COLUMN_SIDECAR_SUBNET_COUNT * i + subnetId
      result.add(ColumnIndex(index))
  res.sort()
  res

proc get_custody_columns*(node_id: NodeId, custody_subnet_count: uint64): Result[seq[ColumnIndex], cstring] =
    
    # assert custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT
    if not (custody_subnet_count <= DATA_COLUMN_SIDECAR_SUBNET_COUNT):
        return err("Eip7594: Custody subnet count exceeds the DATA_COLUMN_SIDECAR_SUBNET_COUNT")

    var subnet_ids: HashSet[uint64]
    var current_id = node_id

    while subnet_ids.len < int(custody_subnet_count):
    
        # var subnet_id_bytes: seq[byte]
        let subnet_id_bytes = eth2digest(current_id.toBytesLE().toOpenArray(0,8))
        var subnet_id = bytes_to_uint64(subnet_id_bytes.data) mod DATA_COLUMN_SIDECAR_SUBNET_COUNT
        
        if subnet_id notin subnet_ids:
            subnet_ids.incl(subnet_id)

        if current_id == UInt256.high.NodeId:
            # Overflow prevention
            current_id = NodeId(StUint[256].zero)
        current_id += NodeId(StUint[256].one)

    # assert len(subnet_ids) == len(set(subnet_ids))
    if not (subnet_ids.len == subnet_ids.len):
        return err("Eip7594: Subnet ids are not unique")

    # columns_per_subnet = NUMBER_OF_COLUMNS // DATA_COLUMN_SIDECAR_SUBNET_COUNT
    let columns_per_subnet = NUMBER_OF_COLUMNS div DATA_COLUMN_SIDECAR_SUBNET_COUNT
    
    ok(sortedColumnIndices(ColumnIndex(columns_per_subnet), subnet_ids))


# #### `compute_extended_matrix`


# proc compute_extended_matrix(blobs: openArray[Blob]): ExtendedMatrix =
#     discard """
#     Return the full ``ExtendedMatrix``.

#     This helper demonstrates the relationship between blobs and ``ExtendedMatrix``.
#     The data structure for storing cells is implementation-dependent.
#     """
#     # extended_matrix = []
#     # for blob in blobs:
#     #     extended_matrix.extend(compute_cells(blob))
#     # return ExtendedMatrix(extended_matrix)


# #### `recover_matrix`


# proc recover_matrix(cells_dict: Table[(BlobIndex, CellID), Cell], blob_count: uint64): ExtendedMatrix =
#     discard """
#     Return the recovered ``ExtendedMatrix``.

#     This helper demonstrates how to apply ``recover_all_cells``.
#     The data structure for storing cells is implementation-dependent.
#     """
#     # extended_matrix: List[Cell] = []
#     # for blob_index in range(blob_count):
#     #     cell_ids = [cell_id for b_index, cell_id in cells_dict.keys() if b_index == blob_index]
#     #     cells = [cells_dict[(BlobIndex(blob_index), cell_id)] for cell_id in cell_ids]

#     #     all_cells_for_row = recover_all_cells(cell_ids, cells)
#     #     extended_matrix.extend(all_cells_for_row)
#     # return ExtendedMatrix(extended_matrix)


# #### `get_data_column_sidecars`


# proc get_data_column_sidecars(signed_block: SignedBeaconBlock,
#                              blobs: openArray[Blob]): openArray[DataColumnSidecar] =
#     # signed_block_header = compute_signed_block_header(signed_block)
#     # block = signed_block.message
#     # kzg_commitments_inclusion_proof = compute_merkle_proof(
#     #     block.body,
#     #     get_generalized_index(BeaconBlockBody, 'blob_kzg_commitments'),
#     # )
#     # cells_and_proofs = [compute_cells_and_kzg_proofs(blob) for blob in blobs]
#     # blob_count = len(blobs)
#     # cells = [cells_and_proofs[i][0] for i in range(blob_count)]
#     # proofs = [cells_and_proofs[i][1] for i in range(blob_count)]
#     # sidecars = []
#     # for column_index in range(NUMBER_OF_COLUMNS):
#     #     column = DataColumn([cells[row_index][column_index]
#     #                          for row_index in range(blob_count)])
#     #     kzg_proof_of_column = [proofs[row_index][column_index]
#     #                            for row_index in range(blob_count)]
#     #     sidecars.append(DataColumnSidecar(
#     #         index=column_index,
#     #         column=column,
#     #         kzg_commitments=block.body.blob_kzg_commitments,
#     #         kzg_proofs=kzg_proof_of_column,
#     #         signed_block_header=signed_block_header,
#     #         kzg_commitments_inclusion_proof=kzg_commitments_inclusion_proof,
#     #     ))
#     # return sidecars
#     discard
