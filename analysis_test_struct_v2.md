# Static Analysis: `test-struct-v2`

## File(s) defining the test

| Artifact | Path |
|---|---|
| Source | `tests/test_struct_v2.cpp` (474 lines, single file) |
| Makefile target | `Makefile:162-163` — `test-struct-v2` builds and runs `$(BUILD)/test_struct_v2` |
| Build rule | `Makefile:77-78` — compiles `tests/test_struct_v2.cpp` (header-only library) |

## Data structures

- **`Cipher`** — `vector<Layer> L`, `vector<Edge> E`, scalar `c0`
- **`Layer`** — `RRule rule` (BASE=0 or PROD=1), `RSeed seed`, `pa`, `pb`
- **`Edge`** — `layer_id`, `idx`, `ch` (sign), `w` (Fp weight), `s` (BitVec)
- **`Fp`** — 128-bit field element

## The 12 sub-tests

### [1] Signal/noise separation (`test_signal_noise`)
Computes signed weighted terms per layer-0 edge and their total sum. Enumerates all C(n,8) subsets. **Fails if any 8-subset sums to the total.** Checks that signal is spread across all edges.

### [2] Weight zero-sum (`test_weight_zero`)
Enumerates all C(n,8) subsets of signed layer-0 weights. **Fails if any 8-subset sums to zero.** No small-support zero-sum relation should exist.

### [3] GCD / small-ratio (`test_gcd`)
For all pairs of layer-0 weights, checks if their ratio is +/-k for k in [1..100]. **Fails if any pair has a small-integer ratio.**

### [4] Linear relations (`test_linear`)
For triples of weights (up to 15 edges), searches all (a,b,c) in [-10,10]^3 (nonzero) for a*w[i]+b*w[j]+c*w[k]=0. **Fails if any such relation exists.**

### [5] Index distribution (`test_idx_dist`)
Counts occurrences of each `idx` in layer-0 edges. **Fails if any index appears more than 2 times.**

### [6] Cross-layer randomness (`test_cross_layer`)
For each pair of layers, takes first edge weight from each, checks ratio against +/-k for k in [1..1000]. **Fails if any small-integer ratio is found.**

### [7] PRF uniqueness (`test_prf_unique`)
Encrypts the same value 10 times, checks first-edge weight for collisions. **Fails if any two match.**

### [8] R non-recoverability (`test_r_recovery`)
Computes true R via secret key. Checks if any layer-0 edge weight divided by small k equals R. **Fails if R is recoverable.**

### [9] Delta != R (`test_delta_neq_r`)
Over 100 trials, checks if any noise delta equals +/-R. **Fails on collision.**

### [10] Noise sum != 0 (`test_noise_sum_nonzero`)
Over 100 trials, sums all noise deltas for a layer. **Fails if sum is zero.**

### [11] Multi-encryption structure (`test_multi_enc_struct`)
Runs signal/noise separation (test [1] logic) on 50 independent encryptions. **Fails if any has a size-8 subset reproducing the total.**

### [12] Delta domain separation (`test_delta_domain_separation`)
For 256 group IDs, computes deltas for kind=0 and kind=1. **Fails if any duplicates within or across kinds.**

## Assumptions about ciphertext structure

1. Ciphertexts have a layered structure; layer 0 is the primary layer.
2. Each edge carries a weight (field element), index, sign, and layer assignment.
3. Weights should behave as random — no small-integer ratios, no low-coefficient linear relations, no small-support zero-sums.
4. Layers use independent randomness; cross-layer weight ratios should not be small integers.
5. Different encryptions of the same value produce distinct edge weights.
6. Indices in layer-0 are spread out (max reuse <= 2).
7. Noise deltas are domain-separated and never equal the blinding factor R.
8. Typical ciphertexts have 8-40 layer-0 edges.

## What ciphertexts would fail

- Degenerate/correlated weights (small-integer ratios, linear dependencies)
- Weight cancellation (8-element signed zero-sums)
- Concentrated signal (small subset explains the total)
- Index clustering (any idx appearing 3+ times)
- Correlated cross-layer randomness
- Trivially extractable blinding factor R
- PRF collisions across encryptions
- Noise that cancels to zero or equals R

## Specific questions

### Would a ciphertext with multiple BASE layers violate this test?
**No.** The test never inspects `Layer::rule`. It filters edges by integer `layer_id`, not by BASE/PROD. Multiple BASE layers are invisible to the test unless they happen to produce small-integer weight ratios (caught by test [6]).

### Would repeated indices (idx) inside one ciphertext violate this test?
**Depends on count.** Test [5] allows max reuse of 2. Index appearing 1-2 times: passes. Index appearing 3+ times: **fails**.

### Would shared indices across multiple ciphertexts violate this test?
**No.** No test compares indices across ciphertexts. Test [7] only compares weights. Test [11] analyzes each encryption independently. Cross-ciphertext index sharing is invisible to this suite.

## Summary

`test-struct-v2` is a 12-part structural regression test that validates invariants of PVAC ciphertexts without testing decryption correctness. It checks that edge weights are algebraically independent (no small-integer ratios, zero-sums, or linear relations), that signal contribution is spread across all edges (not concentrated in small subsets), that indices are distributed without heavy reuse, that per-layer and per-encryption randomness is unique and independent, and that noise values are domain-separated and never cancel or collide with blinding factors. Any ciphertext exhibiting algebraic regularity, weight collisions, index clustering, or noise cancellation is flagged as a structural failure.
