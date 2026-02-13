# ZKsync Airbender RISC-V zkVM — Security Audit Report

**Target:** ZKsync Airbender (github.com/matter-labs/zksync-airbender)  
**Platform:** Immunefi Bug Bounty ($100K max payout)  
**Date:** February 12, 2026  
**Auditor:** Daniel (independent security researcher)  
**Scope:** Full STARK/AIR proof system — verifier, constraint system, composition layer, delegation circuits  
**Codebase:** 963 files, STARK over Mersenne31 field with quartic extension

-----

## Executive Summary

A comprehensive security audit was conducted on the ZKsync Airbender RISC-V zkVM proof system, covering the constraint system, verifier implementation, delegation circuits (Blake2s, BigInt), the cross-circuit composition layer (`full_statement_verifier`), and the recursive proof aggregation mechanism.

**No critical or high-severity vulnerabilities were identified.**

The system demonstrates a mature, well-engineered architecture with proper cryptographic binding between circuits, sound memory arguments, correctly implemented FRI verification, and robust Fiat-Shamir transcript management.

-----

## Architecture Overview

Airbender is a STARK/AIR-based proof system that proves correct execution of RISC-V programs. The architecture consists of:

1. **Main RISC-V circuit** — constrains CPU execution (decode, ALU, memory, branching)
1. **Delegation circuits** — Blake2s (hashing) and BigInt (256-bit arithmetic) off-loaded from the main circuit
1. **Composition layer** (`full_statement_verifier`) — verifies multiple circuit proofs and checks cross-circuit consistency
1. **Recursive aggregation** — universal verifier that aggregates proofs across recursion layers

The proof system operates over Mersenne31 (p = 2³¹ − 1) with a degree-4 extension field (Mersenne31Quartic), targeting ~81 bits of security via 53 FRI queries and 28-bit proof-of-work.

-----

## Components Audited

### 1. Core Verifier (`verifier/`, `verifier_common/`)

**Constraint system compilation and evaluation:**

- Boolean invariant enforcement via `Invariant::Boolean` metadata correctly translates to `x * (x - 1) = 0` constraints during quotient polynomial compilation.
- `Num`↔`Boolean` type conversions preserve constraint metadata through `CircuitOutput`.
- Quotient polynomial evaluation at challenge point `z` properly accumulates all constraint contributions with correct divisor polynomials.

**Field arithmetic (Mersenne31, Mersenne31Complex, Mersenne31Quartic):**

- Reduction modulo 2³¹ − 1 uses bitwise techniques (`(x >> 31) + (x & P)`), correctly handles the double-reduction edge case where intermediate sum equals P.
- Extension field multiplication uses Karatsuba for the complex extension and schoolbook for the quartic, with correct coefficient manipulation.
- Inverse computation via Fermat’s little theorem with verified exponent decomposition.
- FMA (fused multiply-add) variants produce identical results to non-FMA paths.

**VERIFIED SOUND** — No vulnerabilities found.

### 2. Memory Argument (ShuffleRAM)

**Grand product accumulation:**

- Memory argument uses a multiplicative grand product over `(is_register, address, timestamp, value)` tuples linearized with random challenges.
- Read-write pairs are linked: each read sees the last write to the same address.
- Timestamp ordering enforced via borrow-chain comparison: `read_ts < write_ts` decomposed into `(1<<19)*borrow + read_ts_low - write_ts_low` with range checks.
- Initial register writes (value=0, timestamp=0) and final register reads are explicitly incorporated into the accumulator in the composition layer.

**Lazy-init boundary values:**

- ShuffleRAM uses lazy initialization (first access can be a read if the address wasn’t previously written).
- Cross-circuit lazy-init ordering is enforced: `first_current_addr > last_previous_addr`, or the previous circuit’s last entry is zero-padding.
- Teardown values (value and timestamp) must be zero for the zero-padding case.

**VERIFIED SOUND** — No vulnerabilities found.

### 3. Lookup Argument (LogUp)

- Table IDs are included in the linearization to prevent cross-table confusion.
- Multiplicity-weighted inverse accumulation: `sum(multiplicity_i / (linearized_entry_i + gamma)) = 0`.
- The verifier’s `batch_inverse_checked` correctly handles the zero-divisor case (rejects if any divisor is zero, which would indicate a Schwartz-Zippel failure).

**VERIFIED SOUND** — No vulnerabilities found.

### 4. FRI Verification

**Folding formula:**

```
folded = f(x) + f(-x) + (alpha / x) * (f(x) - f(-x))
```

- Correctly implements the standard degree-halving fold (up to a factor of 2, which is absorbed into the commitment scheme).
- Leaf value verified against accumulated expected value: `assert_eq!(*expected_value, value_at_expected_index)` — prevents leaf-swapping attacks.
- Evaluation point and roots iteratively squared across folding rounds.
- Domain index, tree index, and domain size properly adjusted after each fold.
- FMA code path produces identical results to the non-FMA path.

**Final monomial check:**

- After all FRI rounds, remaining polynomial coefficients are read from the proof.
- The polynomial is evaluated at the challenge point and compared against the accumulated FRI value.
- `taus_in_domain_by_half` correction factor applied to account for the coset offset.

**VERIFIED SOUND** — No vulnerabilities found.

### 5. Fiat-Shamir Transcript (Blake2s)

- Transcript uses Blake2s with a buffering wrapper (`Blake2sBufferingTranscript`).
- Challenge derivation sequence: setup caps → witness caps → stage 2 caps + accumulators → quotient caps → evaluations → FRI oracles.
- All prover messages are committed before challenges are derived.
- `from_nonreduced_u32` is used for challenge generation, properly reducing modulo P.

**VERIFIED SOUND** — No vulnerabilities found.

### 6. DEEP Polynomial Consistency

- The verifier recomputes DEEP polynomial values from openings at `z` and `z*omega`, then checks consistency with FRI leaf values.
- Both `z` and `z*omega` evaluation points are properly handled.
- The DEEP combination uses randomized linear combination with the DEEP challenge `alpha`.

**VERIFIED SOUND** — No vulnerabilities found.

### 7. Delegation Circuits

#### 7a. Blake2s Delegation Circuit

**ABI:** x10 (state pointer, 24 words), x11 (input pointer, 16 words), x12 (round bitmask), x13 (control mask)

**G-function mixing:**

- 4 column G-functions followed by 4 diagonal G-functions per round — correct Blake2s structure.
- Rotation operations (ROTR 16, 12, 8, 7) implemented via bit decomposition with lookup tables (Xor, Xor3, Xor4, Xor7, Xor9).
- Carry chains for modular addition are properly constrained with Boolean carry variables.
- SIGMA permutation selection uses orthogonal bitmask from 10-bit round decomposition.

**Compression mode:**

- IV initialization, input selection (normal vs. Merkle tree mode), and final XOR are conditional on control bits.
- Reduced to 7 rounds (standard optimization for STARK systems where collision resistance, not preimage resistance, is the requirement).

**VERIFIED SOUND** — No vulnerabilities found.

#### 7b. BigInt Delegation Circuit

**ABI:** x10 (pointer to a, R/W), x11 (pointer to b, RO), x12 (control mask + result flag, R/W)

**Operations:** ADD, SUB, SUB_NEGATE, MUL_LOW, MUL_HIGH, EQ, MEMCOPY (with optional CARRY bit)

**Operation selection:**

- Orthogonal bitmask: `sum(control_bits) * (sum(control_bits) - 1) = 0` enforces exactly 0 or 1 operation selected.
- When no operation selected (execute=false), output forced to zero via `output = sum(flag_i * result_i)`.

**Addition/subtraction:**

- Virtual A/B/C limbs selected via quadratic constraints: `A + B = C + 2^256 * overflow`.
- 16 Boolean intermediate carries, first limb uses external carry_or_borrow input.

**Multiplication:**

- Byte-level schoolbook multiplication: `product[i] = sum(a_bytes[j] * b_bytes[k])` for appropriate index pairs.
- Carry chain with range-checked carry values (9-13 bit widths).
- Product split into low/high 256-bit halves for MUL_LOW/MUL_HIGH.

**Zero-check:**

- Standard `(x) * zero_flag = 0` and `(x) * inv = 1 - zero_flag` technique.
- EQ computes `all_zeroes = multi_and(is_zero(result[i]))`, result = `all_zeroes && !overflow`.

**VERIFIED SOUND** — No vulnerabilities found.

### 8. Delegation Argument Linking

**Main circuit side (quotient.rs lines 8620-8635):**

```
denom = challenges[2] * ts_high + challenges[1] * ts_low + challenges[0] * mem_offset + type + gamma
constraint: denom * stage_2[48] - multiplicity = 0
```

**Delegation circuit side (compile_layout.rs):**

- Delegation request includes: execute flag, memory_offset_high, timestamp.
- Register accesses use timestamp comparison (borrow chain) to enforce `read_ts < write_ts`.
- Indirect memory accesses derive addresses as `addr = register_value + offset` with carry handling for unaligned access.
- Alignment enforced via range-check on shifted register value when indirects are present.

**Cross-circuit binding:**

- Main circuit accumulates `+1/denom` for each delegation request.
- Delegation circuit accumulates `multiplicity/denom` for each processed request.
- Composition layer verifies: main circuit accumulators sum - delegation circuit accumulators sum = 0.

**VERIFIED SOUND** — No vulnerabilities found.

### 9. Composition Layer (`full_statement_verifier`)

This is the most critical component — it ties all circuit proofs together and verifies global consistency.

**Main circuit chain verification:**

- Circuit sequence monotonicity: `circuit_sequence == i` for each i in 0..num_circuits.
- Delegation type = 0 for all main circuits.
- Setup caps identical across all main circuit instances (same program).
- Memory and delegation challenges identical across all instances.
- Lazy-init boundary ordering enforced (see §2 above).
- PC continuity: `start_pc[i+1] == end_pc[i]`, starting from PC=0.
- Memory grand product: multiplicatively accumulated across all circuits.
- Delegation set accumulator: additively accumulated across main circuits.

**Delegation circuit verification:**

- Delegation types processed in strict ascending order.
- Each delegation circuit’s setup caps match hardcoded expected values (verification key).
- Memory and delegation challenges match the main circuit’s challenges.
- Memory grand product: multiplicatively accumulated.
- Delegation set accumulator: **subtracted** (requests and responses cancel).
- Total delegation requests < field_characteristic (Mersenne31) — prevents accumulator overflow.

**Final consistency checks:**

- Transcript-derived challenges match those used in all proofs (Fiat-Shamir binding).
- `memory_grand_product_accumulator == ONE` (all memory accesses matched).
- `delegation_set_accumulator == ZERO` (all delegation requests served).
- Register contribution incorporated into memory argument before final check.

**Recursion chain:**

- Base layer: output registers x18-x25 must be zero; chain = `blake([0;8] || end_params)`.
- Recursion layer: x18-x25 contain hash chain; prover provides preimage; chain extends or continues.
- Proof merging (modes 4, 6): Keccak-based rolling hash over circuit outputs with VK chain equality check.

**VERIFIED SOUND** — No vulnerabilities found.

-----

## Informational Findings

### INFO-01: output[7] Zero-Padding in Proof Merging

**Location:** `tools/verifier/src/main.rs`, `merge_recursive_circuit_output()`, lines 233-253

**Description:** When combining multiple recursive proofs (modes 4 and 6), the merge function zero-pads `output[7]` (corresponding to register a7/x17) rather than including its actual value in the hash:

```rust
hasher.update(&[0u32]);  // replaces output[7]
for val in &first[0..7] { hasher.update(&[*val]); }
```

The code contains a TODO comment: *“in the future, check explicitly that output1[7] && output2[7] == 0.”*

**Impact:** If a program uses register a7 for meaningful output data, this value will be silently dropped during proof combination. Two programs producing different a7 values but identical a0-a6 values would produce the same merged output.

**Risk:** Low — this is a documented design limitation, not an exploitable vulnerability. The outer protocol must ensure a7 is unused or zero when proof combination is employed.

**Recommendation:** Add explicit `assert_eq!(first[7], 0)` and `assert_eq!(second[7], 0)` as indicated by the TODO.

### INFO-02: Timestamp +1 Offset Required for Soundness

**Location:** `prover/src/prover_stages/mod.rs`, line 326

**Description:** The prover’s setup creates an initial row with timestamp +1 offset. This is mandatory for soundness — without it, row 0’s lazy-init would fail because the timestamp comparison requires `read_ts < write_ts`, and timestamp 0 cannot be less than any valid write timestamp.

**Risk:** None (correctly implemented), but the requirement is implicit.

**Recommendation:** Add a `// SAFETY: Required for soundness — see timestamp comparison in ShuffleRAM` comment.

### INFO-03: Security Parameter Margin

**Description:** The system targets ~81 bits of security: 53 FRI queries × 1 bit + 28-bit PoW = 81 bits. While this meets the stated 80-bit target, the margin is thin.

**Recommendation:** Consider increasing PoW to 30-32 bits for additional safety margin, or adding 1-2 more FRI queries.

-----

## Attack Surfaces Investigated (No Findings)

The following attack vectors were systematically investigated and found to be properly mitigated:

1. **Field arithmetic edge cases** — Mersenne31 zero representation (0 vs P), extension field multiplication overflow, inverse of zero
1. **Constraint system bypass** — Boolean invariant stripping during type conversion, missing constraints for decoded instruction fields
1. **Memory argument forgery** — Timestamp ordering manipulation, lazy-init boundary confusion, register contribution omission
1. **Lookup table confusion** — Cross-table ID collision, multiplicity manipulation
1. **FRI soundness** — Leaf value swapping, incorrect folding formula, evaluation point desynchronization
1. **Fiat-Shamir manipulation** — Transcript forking, challenge reuse across circuits, weak randomness
1. **Delegation argument decoupling** — Type ID mismatch, timestamp unbinding, accumulator imbalance
1. **Composition layer bypass** — Challenge inconsistency across circuits, PC discontinuity, lazy-init overlap, accumulator overflow (prevented by `< field_characteristic` check)
1. **Recursion chain forgery** — VK chain mismatch, preimage manipulation, hash chain extension attack
1. **Algebraic attacks** — Schwartz-Zippel failure probability (mitigated by quartic extension: ~2^{-124} per check)

-----

## Security Parameters

|Parameter       |Value                      |Notes                                         |
|----------------|---------------------------|----------------------------------------------|
|Base field      |Mersenne31 (2³¹ − 1)       |~31-bit prime                                 |
|Extension field |Quartic (Mersenne31Quartic)|~124-bit security per algebraic check         |
|FRI queries     |53                         |53 bits from FRI                              |
|Proof-of-work   |28 bits                    |28 bits from PoW                              |
|Total security  |~81 bits                   |Meets 80-bit target                           |
|Blake2s rounds  |7 (reduced)                |Standard for STARK (collision resistance only)|
|Max trace length|2²² - 2²⁵ rows             |Depends on circuit variant                    |

-----

## Files Audited

**Core verifier:**

- `verifier_common/src/fri_folding.rs` (284 lines)
- `verifier_common/src/lib.rs` (156 lines)
- `verifier/src/generated/quotient.rs` (~9400 lines, spot-checked)
- `field/src/` — Mersenne31, Complex, Quartic implementations

**Constraint system:**

- `cs/src/cs/circuit.rs` — constraint compilation, is_zero, Boolean
- `cs/src/one_row_compiler/` — constraint layout, delegation binding
- `cs/src/types.rs` — split_into_bitmask, type system

**Delegation circuits:**

- `cs/src/delegation/blake2_round_with_extended_control/mod.rs` (912 lines)
- `cs/src/delegation/blake2_single_round/mod.rs` (1368 lines)
- `cs/src/delegation/bigint_with_control/mod.rs` (837 lines)

**Composition layer:**

- `full_statement_verifier/src/lib.rs` (526 lines) — **critical**
- `tools/verifier/src/main.rs` (281 lines) — universal verifier + proof merging
- `execution_utils/src/verifiers.rs` (150 lines) — oracle data generation
- `execution_utils/src/recursion.rs` (279 lines) — recursion strategy

**Prover (reference for verifier correctness):**

- `prover/src/prover_stages/mod.rs` (873 lines)
- `prover/src/prover_stages/stage2.rs` (2024 lines, spot-checked)
- `prover/src/definitions/mod.rs` (373 lines)

-----

## Conclusion

The ZKsync Airbender RISC-V zkVM proof system is well-designed and correctly implemented. No soundness vulnerabilities were identified across the verifier, constraint system, delegation circuits, or composition layer. The three informational findings are low-risk items that do not affect the system’s cryptographic soundness.

The architecture demonstrates proper separation of concerns between circuit-level verification and cross-circuit composition, with robust Fiat-Shamir binding, correct memory argument construction, and sound delegation argument linking. The recursive proof aggregation mechanism correctly maintains proof chain integrity through hash-based commitments with verification key binding.

**Verdict: No vulnerabilities eligible for Immunefi bounty submission identified.**
