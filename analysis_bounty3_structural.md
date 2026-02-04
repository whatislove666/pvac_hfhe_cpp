# Bounty3 Structural Analysis: `seed.ct`

Scope: Only `bounty3_data/` and the code paths that produce it.
Constraint: No sk.bin, no code execution, no cryptographic proofs.

---

## 1. Conceptual model: how a ciphertext in seed.ct is composed

### The data in seed.ct

`seed.ct` is a serialized vector of `Cipher` objects produced by `enc_text()`.
The plaintext is a string of the form `"mnemonic: <12 words>, number: <N>"`,
encoded as:

| Index  | What it encrypts                     | Encryption function    | Layers |
|--------|--------------------------------------|------------------------|--------|
| cts[0] | message length (uint64)              | `enc_value` (masked)   | 2 BASE |
| cts[1] | bytes 0-14 of the string             | `enc_fp_depth` (direct)| 1 BASE |
| cts[2] | bytes 15-29                          | `enc_fp_depth` (direct)| 1 BASE |
| ...    | ...                                  | ...                    | 1 BASE |
| cts[N] | final block (possibly partial)       | `enc_fp_depth` (direct)| 1 BASE |

Each 15-byte plaintext block is packed little-endian into an Fp (128-bit field element)
via `pack_15_bytes_to_fp`. `cts[0]` uses `enc_value_depth` which splits the plaintext
into two random shares (`p+m` and `-m`) and fuses two independent `synth` outputs —
hence 2 BASE layers. All other ciphertexts use `enc_fp_depth` → `core::synth` directly,
producing exactly 1 BASE layer.

### Anatomy of a single-layer ciphertext (cts[1..N])

`core::synth(pk, sk, v, depth)` does the following:

1. **Create BASE layer**: random 128-bit nonce, derive `ztag` from `pk.canon_tag`.
2. **Compute entropy budget**: `n2` noise 2-tuples + `n3` noise 3-tuples.
   With bounty3 params and depth=2: n2=4, n3=2 (6 noise groups total).
3. **Generate noise deltas**: `delta[t] = prf_R_noise(pk, sk, seed')` for each noise group.
   The noise aggregate `agg = Σ delta[t]`.
4. **Compute R** = `prf_R(pk, sk, layer_seed)` — the per-layer blinding factor.
5. **Adjusted plaintext**: `va = v - agg` (subtract noise aggregate from plaintext).
6. **Build signal graph** (8 SigNodes):
   - 7 nodes with fresh unique indices and random coefficients.
   - 1 node with a coefficient **solved** so that the signed weighted sum
     `Σ ±coef_i * powg_B[idx_i] = va`.
   - All signal edge weights: `w = coef * R`.
7. **Build noise 2-tuples** (2 edges each, n2 total):
   - For delta[t], produce edges (a, b) such that their signed weighted
     sum = `delta[t]`. Weights: `ra * R`, `rb * R`.
8. **Build noise 3-tuples** (3 edges each, n3 total):
   - Same idea, 3 edges per delta. Weights: `ra * R`, `rb * R`, `rc * R`.
9. **Merge**: combine edges at the same `(layer_id, idx, sign)` by adding weights and
   XOR-ing sigma vectors. With B=337 and ~22 edges, overlaps are rare.
10. **Permute**: randomly shuffle edge order.

### The critical structural property

**Every edge weight in a single-layer ciphertext is exactly `coef_i * R`**,
where `R` is the same per-layer blinding factor for all edges.

This means the publicly computable **g-sum**:

```
G = Σ_edges ±w_i * powg_B[idx_i]
  = R * Σ ±coef_i * powg_B[idx_i]
  = R * (va + Σ delta_t)
  = R * v
```

**The g-sum of a single-layer ciphertext is `R * plaintext_value`.**
Both `G` and `powg_B` are fully public. `R` and `v` are secret.

### Edge roles (invisible after permutation)

| Role          | Count (depth=2)       | Index selection   | Weight structure      |
|---------------|-----------------------|-------------------|-----------------------|
| Signal        | 8                     | `Selector::fresh()` (unique, marked) | 7 random + 1 solved |
| Noise 2-tuple | 2 × n2 = 8           | raw random + `avoid(a)` | ra random, rb solved |
| Noise 3-tuple | 3 × n3 = 6           | raw random + `avoid(a)` + `avoid(a,b)` | ra,rb random, rc solved |

After permutation, you see ~22 edges with random-looking weights at various indices.
You cannot visually tell which edges are signal and which are noise.

### What an observer sees without sk

For each ciphertext:
- Layer metadata: rule (BASE/PROD), seed (ztag, nonce), or parent indices (pa, pb)
- Edge data: `layer_id`, `idx` (0..336), `ch` (sign ±1), `w` (128-bit Fp), `s` (8192-bit sigma vector)
- Constant term `c0` (always 0 for synth outputs)
- The public key pk, including `powg_B[0..336]`

Computable quantities:
- **G-sum** per layer: `G = Σ ±w_i * powg_B[idx_i]` — this equals `R * v`
- **Edge count** per ciphertext — reveals the depth_hint (metadata leakage)
- **Index distribution** — which of the 337 indices are used
- **Weight norms** — Σ w_i^2, Σ |w_i|, etc.
- **Sigma vectors** — LPN samples sharing the same secret across all ciphertexts

---

## 2. Blind spots of test-struct-v2

### What IS enforced (12 sub-tests)

| # | Test | Invariant | Order |
|---|------|-----------|-------|
| 1 | signal/noise | No size-8 subset of signed weighted terms = total sum | Linear (subset sum) |
| 2 | weight zero | No size-8 subset of signed weights sums to 0 | Linear (subset sum) |
| 3 | gcd | No pair of weights has ratio ±k, k ∈ [1,100] | Linear (pairwise ratio) |
| 4 | linear | No triple has low-coef relation a·w_i+b·w_j+c·w_k=0 | Linear (3-way) |
| 5 | idx dist | No index appears >2 times in layer-0 edges | Counting |
| 6 | cross-layer | Cross-layer first-edge weight ratio not small integer | Linear (pairwise ratio) |
| 7 | prf unique | 10 encryptions of same value → distinct first weights | Collision (within layer) |
| 8 | R recovery | w_i/k ≠ R for small k | Linear (weight-to-R ratio) |
| 9 | delta≠R | Noise deltas never equal ±R | Collision |
| 10| noise sum | Aggregate noise ≠ 0 | Linear (sum) |
| 11| multi-enc | Repeat of test 1 across 50 encryptions | Linear (subset sum) |
| 12| domain sep | Noise deltas unique within and across kind | Collision |

### What is explicitly NOT enforced

| Gap | Description | Why it matters |
|-----|-------------|----------------|
| **No quadratic weight tests** | No test checks `Σ w_i²`, `Σ w_i·w_j`, `G²`, or any degree-2+ polynomial of weights | Quadratic statistics can cancel R (see §3) |
| **No layer-rule validation** | `Layer::rule` (BASE vs PROD) is never inspected | A forged cipher with wrong rule types passes all tests |
| **No cross-ciphertext index comparison** | Index reuse across different ciphertexts is unexamined | Shared indices between ciphertexts could leak structural info |
| **No sigma vector (s) analysis** | The 8192-bit `s` fields on edges are completely ignored | These are LPN samples sharing a global secret — the primary cryptographic attack surface |
| **No edge-count consistency check** | The number of edges isn't validated against expected noise budget | Edge counts reveal depth_hint directly (metadata leakage) |
| **No second-order statistics** | No variance, covariance, or distribution tests of weight populations | Weight distributions within a ciphertext might fingerprint signal vs noise edges |
| **No aggregation tests across layers/ciphertexts** | G-sum products, cross-ciphertext correlations completely unchecked | ct_square's target is literally the g-sum product — this is the stated hint |
| **No known-plaintext tests** | No test considers what happens when parts of the plaintext are known | With known prefix "mnemonic: ", candidate R values can be enumerated |
| **No tuple-structure detection** | No test tries to identify which edges form noise 2-tuples or 3-tuples | If tuples can be identified, signal/noise separation becomes possible |
| **No weight norm ratio tests** | Ratios like G²/Σw² (which cancel R) are never computed | These are R-independent observables |

---

## 3. Interpreting the hint: "ct_square is where we all meet together"

### What ct_square does algebraically

`ct_square(pk, A)` in `include/pvac/ops/arithmetic.hpp:220`:

1. Computes the g-sum per layer: `gA[l] = Σ_edges_in_l ±w·powg_B[idx]`
2. For each pair of layers (la, lb) with la ≤ lb, creates a PROD layer whose **target** is:
   - `gA[la] * gA[lb]` if la = lb (self-product)
   - `2 * gA[la] * gA[lb]` if la ≠ lb (cross-product, doubled for symmetry)
3. Each target is **repackaged** into S=8 fresh random edges via `emit_repack_edges`

For a single-layer ciphertext (most of seed.ct):
- Only one layer (layer 0), so only one product: `gA[0]²`
- `gA[0] = G = R * v`
- **Target = G² = R² · v²**

### "Where we all meet together"

The phrase "we all" refers to **every edge in the ciphertext** — signal edges,
noise 2-tuple edges, noise 3-tuple edges. In linear analysis (degree 1), these
contribute independently to the g-sum. But in `ct_square` (degree 2), the expansion

```
G² = (Σ ±w_i · powg_B[idx_i])²
   = Σ_i (w_i · powg_B[idx_i])²  +  2·Σ_{i<j} ±w_i·w_j · powg_B[idx_i]·powg_B[idx_j]
```

contains **every pairwise product** of edge contributions. Signal "meets" noise.
Each noise tuple "meets" every other tuple. This is where they "all meet together."

### Why quadratic structure can leak information when all linear tests pass

All edge weights share the same factor R: `w_i = coef_i * R`.

Any quantity **homogeneous of degree d** in the weights is proportional to `R^d`.
Ratios of same-degree quantities **cancel R entirely**.

| Quantity | Formula | Degree | R-dependence |
|----------|---------|--------|--------------|
| G (g-sum) | Σ ±w_i·powg_B[idx_i] | 1 | R·v |
| Σ w_i² | sum of squared weights | 2 | R²·(Σ coef_i²) |
| G² | g-sum squared | 2 | R²·v² |
| G²/Σw_i² | **ratio** | 0 | **v²/Σcoef_i²** (R-free!) |

The ratio `G²/Σw_i²` is an **R-independent observable** computable entirely from
public data. test-struct-v2 never computes anything like this.

While the denominator `Σcoef_i²` is random per-ciphertext (so the ratio doesn't
directly reveal v), the DISTRIBUTION of this ratio across many ciphertexts, or
its correlation with other R-independent quadratic forms, could be a distinguisher.

More concretely: if you hypothesize a candidate plaintext `v'` for a block,
you can compute `R_candidate = G / v'`. Then:
- `Σ (w_i / R_candidate)²` should equal `Σ coef_i²`
- The resulting coefficient values must be consistent with the known construction
  (7 random field elements + 1 solved for signal, random+solved for noise tuples)
- The coefficient at each index should be consistent with the index's role
  (signal vs noise) given the tuple structure constraints

This cross-validation is QUADRATIC in nature and is invisible to test-struct-v2.

---

## 4. Attack hypotheses

### Hypothesis A: Known-Plaintext G-Sum Enumeration (KPG)

**What is measured:**
The g-sum G_1 for ciphertext cts[1] (first text block).

**What is compared:**
Candidate R values derived from `G_1 / v_candidate` for each possible first
BIP39 word, against structural constraints from the sigma vectors.

**What structural difference is expected:**
The plaintext of cts[1] is `"mnemonic: XXXXX"` (10 known bytes + first 5 chars of
BIP39 word 1). There are 2048 BIP39 words, most unique in their first 5 characters.
For each candidate word w:

1. `v_candidate = pack_15_bytes("mnemonic: " + w[:5])` → a specific Fp value
2. `R_candidate = G_1 / v_candidate`
3. For each edge in cts[1]: `coef_i = w_i / R_candidate`
4. Check: do the coefficients satisfy structural constraints?
   - **Tuple constraint**: noise 2-tuples satisfy `±coef_a·powg_B[a] ±coef_b·powg_B[b] = delta`.
     For the WRONG R, the "deltas" recovered from different tuples will be random.
     For the CORRECT R, the deltas are PRF outputs (indistinguishable from random
     individually, but their aggregate must equal `v - va` which ties to the signal).
   - **Norm constraint**: `G² / Σw² = v² / Σcoef²` must be consistent.
   - **Sigma constraint**: with known R, the LPN labels for prf_R_core can be
     partially reverse-engineered, providing (sample, label) pairs.

**Key insight**: With ~2048 candidates and a sufficiently discriminating quadratic
or structural check, the correct word can be identified. Once word 1 is known,
R_1 is known, and the LPN attack surface (sigma vectors) becomes exploitable.

### Hypothesis B: Quadratic Norm Fingerprinting Across Ciphertexts

**What is measured:**
For each ciphertext i, compute the R-independent ratio:
```
Q_i = G_i² / Σ_j (w_ij)²
```

**What is compared:**
Q values across ciphertexts. Also compute higher-order R-free statistics:
```
Q_diag_i = Σ_j (w_ij · powg_B[idx_ij])²     (degree-2, same-index terms)
Q_cross_i = G_i² - Q_diag_i                   (degree-2, cross-index terms)
```

**What structural difference is expected:**
The signal construction solves for one coefficient to hit a target. For a
SMALL plaintext value v (like a message length ≈ 150), `va = v - agg` is
dominated by the noise aggregate `agg` (a PRF output, large field element).
For a LARGE plaintext value (like a 15-byte text block packed as Fp), `va` has
specific magnitude structure.

The solved coefficient in the signal is:
```
last_coef = (va - Σ_{k=0}^{6} ±random_k · powg_B[pos_k]) / powg_B[pos_7]
```
When `va` is enormous (text block) vs small (length), the solved coefficient's
contribution to the norm differs. Across ciphertexts, the Q values might cluster
by plaintext "type" (length vs text block).

Additionally, the increasing depth_hint (2, 3, 4, ...) changes the noise budget
(more noise tuples → more noise edges), which systematically shifts the Q distribution.
This is metadata leakage: position-in-message is revealed.

### Hypothesis C: Pairwise Weight Product Clustering (Tuple Identification)

**What is measured:**
For each ciphertext, compute all `(n choose 2)` pairwise products:
```
P_{ij} = w_i · w_j · powg_B[idx_i] · powg_B[idx_j]
```

**What is compared:**
Look for subsets of edges whose pairwise products satisfy algebraic constraints:
- **2-tuple signature**: For edges (a, b) forming a noise 2-tuple, the construction
  guarantees `±ra·powg_B[a] ∓ rb·powg_B[b] = delta`. After scaling by R, this is
  a linear relation between two terms. The squared relation:
  `(ra·powg_B[a])² + (rb·powg_B[b])² - 2·ra·rb·powg_B[a]·powg_B[b] = delta²`
  This quadratic constraint on the edge weights can be checked for all candidate
  pairs to identify noise 2-tuples.
- **Signal signature**: The 8 signal edges have `Σ ±coef_i · powg_B[idx_i] = va`,
  and 7 of 8 coefficients are random. The "solved" coefficient has a specific
  algebraic relationship to the others.

**What structural difference is expected:**
Noise 2-tuples are algebraically constrained in a way that differs from random
edge pairs. By testing all `(n choose 2)` pairs for the 2-tuple constraint
(which involves an R-independent check on the ratio structure), noise tuples
can be identified. Once signal edges are separated from noise, the signal's
g-sum directly encodes `R · va`, drastically reducing the search space.

### Hypothesis D: Sigma-Vector LPN Attack (Cryptographic, High-Effort)

**What is measured:**
The sigma vectors `s` (8192-bit BitVecs) on every edge across all ciphertexts.

**What is compared:**
These are LPN samples of the form `H·x_i + e_i` where:
- H is the public parity matrix (available from pk)
- x_i is a sparse binary vector determined by PRG from public edge parameters
- e_i is a sparse noise vector
- The underlying LPN secret `lpn_s_bits` is shared across ALL samples

**What structural difference is expected:**
Each edge provides one LPN sample. With params `lpn_n=4096, lpn_t=16384, tau=1/8`,
the noise rate is 12.5%. Across all ciphertexts (~20+ edges each, ~10+ ciphertexts),
hundreds of LPN samples are available.

Standard LPN attacks (BKW, Gaussian elimination variants) have complexity that
depends on the number of samples, secret dimension, and noise rate. With n=4096
and 12.5% noise, brute-force LPN is infeasible. BUT:
- The x_i vectors are SPARSE (chosen by `prg_choose_k` with a specific weight).
  Sparse secrets dramatically reduce LPN hardness.
- The column selection is deterministic from public parameters — the attacker
  knows which columns of H are XOR'd for each sample.
- If the effective secret weight is small enough, lattice-based or information-set
  decoding attacks become feasible.

This is the most direct cryptographic attack: recover `lpn_s_bits`, reconstruct `sk`,
compute all R values, decrypt everything.

---

## 5. Prioritization

### Ranking

| Rank | Hypothesis | Likelihood | Ease of verification | Hint alignment |
|------|-----------|-----------|---------------------|----------------|
| **1** | **A: Known-Plaintext G-Sum Enumeration** | **High** | **Medium** (requires parsing pk.bin and seed.ct, ~2048 candidates) | **Strong** (g-sum is what ct_square operates on) |
| 2 | C: Pairwise Weight Product Clustering | Medium | Medium-Hard (combinatorial search over edge pairs) | **Strong** (pairwise products = quadratic = ct_square) |
| 3 | B: Quadratic Norm Fingerprinting | Medium-Low | Easy (simple arithmetic over public edge data) | Medium (R-free quantities, but may not discriminate) |
| 4 | D: Sigma-Vector LPN Attack | Medium | Hard (requires implementing LPN solver, analyzing sparsity) | Weak (not related to ct_square hint) |

### Recommended primary path: Hypothesis A (KPG)

**Rationale:**

1. **The g-sum is the linchpin.** For every single-layer ciphertext, `G = R·v`
   is computable from public data. This is EXACTLY the quantity that `ct_square`
   operates on ("where we all meet together"). The hint points directly at g-sums.

2. **Known plaintext reduces the search space drastically.** The first text block
   starts with `"mnemonic: "` (10 bytes known). BIP39 has 2048 words. That's
   2048 candidate values for v_1, each giving a candidate R_1 = G_1/v_1.

3. **Quadratic cross-validation is feasible.** For each candidate R_1, decompose
   all edge weights into coefficients (`coef_i = w_i / R_1`). Check whether the
   coefficients satisfy the algebraic constraints of the signal+noise construction.
   This is a quadratic structural test that test-struct-v2 never performs.

4. **Recovery cascades.** Once one R value is known:
   - The corresponding plaintext block is known (first BIP39 word).
   - The sigma vectors on that ciphertext's edges become labeled LPN samples.
   - With enough labels, the LPN secret can be attacked, recovering sk entirely.
   - From sk, all R values and all plaintext blocks follow.

**Concrete first step:**
Parse pk.bin (load `powg_B[0..336]`). Parse seed.ct (load all ciphertexts).
For each ciphertext cts[i] with i ≥ 1, compute `G_i = Σ ±w·powg_B[idx]`.
For cts[1], enumerate all 2048 BIP39 words as candidates for bytes 10-14,
compute `v_candidate = pack_15_bytes("mnemonic: " + word[:5])`, and
compute `R_candidate = G_1 · fp_inv(v_candidate)`. Then for each candidate,
check whether the resulting coefficients `w_j / R_candidate` are structurally
consistent with the synth construction (e.g., do any pairs of recovered
coefficients satisfy the noise 2-tuple algebraic constraint).
