# Succinct audit details

- Total Prize Pool: $112,500 in USDC
  - HM awards: up to $105,600 in USDC
    - If no valid Highs or Mediums are found, the HM pool is $0
  - QA awards: $4,400 in USDC
  - Judge awards: $2,000 in USDC
  - Scout awards: $500 in USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts September 15, 2025 20:00 UTC
- Ends October 15, 2025 20:00 UTC

**❗ Important notes for wardens**

1. Judging phase risk adjustments (upgrades/downgrades):

- High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
- Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
- As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## Publicly Known Issues

_Note for C4 wardens: Anything included in this `Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

From the security model in the [SP1 Docs](https://docs.succinct.xyz/docs/sp1/security/security-model), the following remains true.

Since SP1 only aims to provide proof of correct execution for the user-provided program, it is crucial for users to make sure that their programs are secure.

SP1 assumes that the program compiled into SP1 is non-malicious. This includes that the program is memory-safe and the compiled ELF binary has not been tampered with. Compiling unsafe programs with undefined behavior into SP1 could result in undefined or even malicious behavior being provable and verifiable within SP1. Therefore, developers must ensure the safety of their code and the correctness of their SP1 usage through the appropriate toolchain. Similarly, users using SP1's patched crates must ensure that their code is secure when compiled with the original crates. SP1 also has [requirements for safe usage of SP1 Precompiles](https://docs.succinct.xyz/docs/sp1/security/safe-precompile-usage), which must be ensured by the developers.

We are also aware that our JALR implementation doesn't clear the least significant bit of the `(rs1 + imm)` value. Since this value is asserted to be a multiple of `4` in the circuit, there are no soundness issues. The only issue that may arise from this is that there might be valid execution where `(rs1 + imm)` value is not even, leading to a potential completeness issue. However, in usual programs compiled through the standard SP1 toolchain, this behavior will not be observed. Note that this clearing of LSB usually only happens on incorrect pointer arithmetic or an unsafe program, so this completeness issue is very minor.

We are also aware that our `generate_trace` function for the `DivRemChip` may panic on debug mode, due to the usage of `abs()` function over `i64`. Since proving is expected to be done on release mode, this issue is informational.

# Overview

![SP1](https://github.com/user-attachments/assets/48ccf1d5-fc4b-49e9-b916-acdb1b427531)

SP1 is the fastest, most-feature complete zero-knowledge virtual machine (zkVM) that can prove the execution of arbitrary Rust (or any LLVM-compiled language) programs. SP1 makes ZK accessible to _any developer_, by making it easy to write ZKP programs in normal Rust code.

## Links

- **Previous audits:** SP1 has undergone audits from [Veridise](https://www.veridise.com/), [Cantina](https://cantina.xyz/), and [KALOS](https://kalos.xyz/) and is recommended for production use. The audit reports are available [here](https://github.com/code-423n4/2025-09-succinct/tree/main/audits).
- **Documentation:** <https://hackmd.io/@rkm0959/HJjChD1iex> and <https://hackmd.io/@rkm0959/rydiLQaqel>
  - [Install](https://docs.succinct.xyz/docs/sp1/getting-started/install)
  - [Docs](https://docs.succinct.xyz/docs/sp1/introduction)
  - [Examples](https://github.com/succinctlabs/sp1/tree/main/examples)
- **Website:** <https://linktr.ee/succinctlabs>
- **X/Twitter:** <https://x.com/SuccinctLabs>
- **[Install](https://docs.succinct.xyz/docs/sp1/getting-started/install)**
- **[Docs](https://docs.succinct.xyz/docs/sp1/introduction)**
- **[Examples](https://github.com/succinctlabs/sp1/tree/main/examples)**
- **Telegram Chat:** <https://t.me/+AzG4ws-kD24yMGYx>

---

# Scope

_See [scope.txt](https://github.com/code-423n4/2025-09-succinct/blob/main/scope.txt)_

### Files in scope

| File | nSLOC |
| ---- | ----- |
| /crates/recursion/circuit/src/basefold/merkle_tree.rs | 108 |
| /crates/recursion/circuit/src/basefold/mod.rs | 544 |
| /crates/recursion/circuit/src/basefold/stacked.rs | 212 |
| /crates/recursion/circuit/src/basefold/tcs.rs | 168 |
| /crates/recursion/circuit/src/basefold/whir.rs | 676 |
| /crates/recursion/circuit/src/basefold/witness.rs | 160 |
| /crates/recursion/circuit/src/challenger.rs | 583 |
| /crates/recursion/circuit/src/dummy/jagged.rs | 317 |
| /crates/recursion/circuit/src/dummy/logup_gkr.rs | 53 |
| /crates/recursion/circuit/src/dummy/mod.rs | 5 |
| /crates/recursion/circuit/src/dummy/shard_proof.rs | 79 |
| /crates/recursion/circuit/src/dummy/sumcheck.rs | 16 |
| /crates/recursion/circuit/src/hash.rs | 245 |
| /crates/recursion/circuit/src/jagged/jagged_eval.rs | 364 |
| /crates/recursion/circuit/src/jagged/mod.rs | 5 |
| /crates/recursion/circuit/src/jagged/verifier.rs | 447 |
| /crates/recursion/circuit/src/jagged/witness.rs | 87 |
| /crates/recursion/circuit/src/lib.rs | 721 |
| /crates/recursion/circuit/src/logup_gkr.rs | 256 |
| /crates/recursion/circuit/src/machine/complete.rs | 96 |
| /crates/recursion/circuit/src/machine/compress.rs | 306 |
| /crates/recursion/circuit/src/machine/core.rs | 169 |
| /crates/recursion/circuit/src/machine/deferred.rs | 189 |
| /crates/recursion/circuit/src/machine/mod.rs | 22 |
| /crates/recursion/circuit/src/machine/public_values.rs | 96 |
| /crates/recursion/circuit/src/machine/root.rs | 52 |
| /crates/recursion/circuit/src/machine/vkey_proof.rs | 139 |
| /crates/recursion/circuit/src/machine/witness.rs | 229 |
| /crates/recursion/circuit/src/machine/wrap.rs | 64 |
| /crates/recursion/circuit/src/shard.rs | 528 |
| /crates/recursion/circuit/src/sumcheck/mod.rs | 266 |
| /crates/recursion/circuit/src/sumcheck/witness.rs | 47 |
| /crates/recursion/circuit/src/symbolic.rs | 58 |
| /crates/recursion/circuit/src/utils.rs | 97 |
| /crates/recursion/circuit/src/witness.rs | 309 |
| /crates/recursion/circuit/src/zerocheck.rs | 220 |
| /crates/recursion/machine/src/builder.rs | 63 |
| /crates/recursion/machine/src/chips/alu_base.rs | 225 |
| /crates/recursion/machine/src/chips/alu_ext.rs | 235 |
| /crates/recursion/machine/src/chips/mem/constant.rs | 191 |
| /crates/recursion/machine/src/chips/mem/mod.rs | 14 |
| /crates/recursion/machine/src/chips/mem/variable.rs | 181 |
| /crates/recursion/machine/src/chips/mod.rs | 10 |
| /crates/recursion/machine/src/chips/poseidon2_helper/convert.rs | 186 |
| /crates/recursion/machine/src/chips/poseidon2_helper/linear.rs | 234 |
| /crates/recursion/machine/src/chips/poseidon2_helper/mod.rs | 3 |
| /crates/recursion/machine/src/chips/poseidon2_helper/sbox.rs | 202 |
| /crates/recursion/machine/src/chips/poseidon2_wide/air.rs | 60 |
| /crates/recursion/machine/src/chips/poseidon2_wide/columns/mod.rs | 1 |
| /crates/recursion/machine/src/chips/poseidon2_wide/columns/preprocessed.rs | 11 |
| /crates/recursion/machine/src/chips/poseidon2_wide/mod.rs | 70 |
| /crates/recursion/machine/src/chips/poseidon2_wide/trace.rs | 144 |
| /crates/recursion/machine/src/chips/prefix_sum_checks.rs | 302 |
| /crates/recursion/machine/src/chips/public_values.rs | 225 |
| /crates/recursion/machine/src/chips/select.rs | 193 |
| /crates/recursion/machine/src/lib.rs | 5 |
| /crates/recursion/machine/src/machine.rs | 237 |
| /crates/prover/src/verify.rs | 519 |
| /crates/core/executor/src/record.rs | 1048 |
| /crates/core/machine/src/adapter/bump.rs | 189 |
| /crates/core/machine/src/adapter/mod.rs | 3 |
| /crates/core/machine/src/adapter/register/alu_type.rs | 181 |
| /crates/core/machine/src/adapter/register/i_type.rs | 305 |
| /crates/core/machine/src/adapter/register/j_type.rs | 144 |
| /crates/core/machine/src/adapter/register/mod.rs | 4 |
| /crates/core/machine/src/adapter/register/r_type.rs | 201 |
| /crates/core/machine/src/adapter/state.rs | 100 |
| /crates/core/machine/src/air/memory.rs | 395 |
| /crates/core/machine/src/air/mod.rs | 42 |
| /crates/core/machine/src/air/operation.rs | 147 |
| /crates/core/machine/src/air/program.rs | 116 |
| /crates/core/machine/src/air/word.rs | 85 |
| /crates/core/machine/src/alu/add_sub/add.rs | 160 |
| /crates/core/machine/src/alu/add_sub/addi.rs | 166 |
| /crates/core/machine/src/alu/add_sub/addw.rs | 186 |
| /crates/core/machine/src/alu/add_sub/mod.rs | 5 |
| /crates/core/machine/src/alu/add_sub/sub.rs | 164 |
| /crates/core/machine/src/alu/add_sub/subw.rs | 173 |
| /crates/core/machine/src/alu/bitwise/mod.rs | 213 |
| /crates/core/machine/src/alu/divrem/mod.rs | 926 |
| /crates/core/machine/src/alu/lt/mod.rs | 211 |
| /crates/core/machine/src/alu/mod.rs | 14 |
| /crates/core/machine/src/alu/mul/mod.rs | 237 |
| /crates/core/machine/src/alu/sll/mod.rs | 356 |
| /crates/core/machine/src/alu/sr/mod.rs | 446 |
| /crates/core/machine/src/bytes/air.rs | 48 |
| /crates/core/machine/src/bytes/columns.rs | 21 |
| /crates/core/machine/src/bytes/mod.rs | 70 |
| /crates/core/machine/src/bytes/trace.rs | 65 |
| /crates/core/machine/src/control_flow/branch/air.rs | 143 |
| /crates/core/machine/src/control_flow/branch/columns.rs | 22 |
| /crates/core/machine/src/control_flow/branch/mod.rs | 12 |
| /crates/core/machine/src/control_flow/branch/trace.rs | 108 |
| /crates/core/machine/src/control_flow/jal/air.rs | 91 |
| /crates/core/machine/src/control_flow/jal/columns.rs | 16 |
| /crates/core/machine/src/control_flow/jal/mod.rs | 12 |
| /crates/core/machine/src/control_flow/jal/trace.rs | 68 |
| /crates/core/machine/src/control_flow/jalr/air.rs | 94 |
| /crates/core/machine/src/control_flow/jalr/columns.rs | 16 |
| /crates/core/machine/src/control_flow/jalr/mod.rs | 12 |
| /crates/core/machine/src/control_flow/jalr/trace.rs | 80 |
| /crates/core/machine/src/control_flow/mod.rs | 6 |
| /crates/core/machine/src/executor.rs | 376 |
| /crates/core/machine/src/global/mod.rs | 252 |
| /crates/core/machine/src/io.rs | 49 |
| /crates/core/machine/src/lib.rs | 121 |
| /crates/core/machine/src/memory/bump.rs | 167 |
| /crates/core/machine/src/memory/consistency/columns.rs | 43 |
| /crates/core/machine/src/memory/consistency/mod.rs | 3 |
| /crates/core/machine/src/memory/consistency/trace.rs | 109 |
| /crates/core/machine/src/memory/global.rs | 363 |
| /crates/core/machine/src/memory/instructions/load/load_byte.rs | 265 |
| /crates/core/machine/src/memory/instructions/load/load_double.rs | 189 |
| /crates/core/machine/src/memory/instructions/load/load_half.rs | 247 |
| /crates/core/machine/src/memory/instructions/load/load_word.rs | 239 |
| /crates/core/machine/src/memory/instructions/load/load_x0.rs | 256 |
| /crates/core/machine/src/memory/instructions/load/mod.rs | 5 |
| /crates/core/machine/src/memory/instructions/mod.rs | 2 |
| /crates/core/machine/src/memory/instructions/store/mod.rs | 4 |
| /crates/core/machine/src/memory/instructions/store/store_byte.rs | 269 |
| /crates/core/machine/src/memory/instructions/store/store_double.rs | 188 |
| /crates/core/machine/src/memory/instructions/store/store_half.rs | 223 |
| /crates/core/machine/src/memory/instructions/store/store_word.rs | 215 |
| /crates/core/machine/src/memory/local.rs | 283 |
| /crates/core/machine/src/memory/mod.rs | 21 |
| /crates/core/machine/src/memory/page_prot.rs | 306 |
| /crates/core/machine/src/memory/page_prot_global.rs | 405 |
| /crates/core/machine/src/memory/page_prot_local.rs | 237 |
| /crates/core/machine/src/operations/add.rs | 65 |
| /crates/core/machine/src/operations/add4.rs | 65 |
| /crates/core/machine/src/operations/add5.rs | 74 |
| /crates/core/machine/src/operations/add_u32.rs | 37 |
| /crates/core/machine/src/operations/address.rs | 113 |
| /crates/core/machine/src/operations/addrs_add.rs | 68 |
| /crates/core/machine/src/operations/addw.rs | 65 |
| /crates/core/machine/src/operations/and_u32.rs | 66 |
| /crates/core/machine/src/operations/bitwise.rs | 85 |
| /crates/core/machine/src/operations/bitwise_u16.rs | 100 |
| /crates/core/machine/src/operations/clk.rs | 67 |
| /crates/core/machine/src/operations/field/field_den.rs | 127 |
| /crates/core/machine/src/operations/field/field_inner_product.rs | 128 |
| /crates/core/machine/src/operations/field/field_op.rs | 423 |
| /crates/core/machine/src/operations/field/field_sqrt.rs | 93 |
| /crates/core/machine/src/operations/field/mod.rs | 6 |
| /crates/core/machine/src/operations/field/range.rs | 98 |
| /crates/core/machine/src/operations/field/util_air.rs | 19 |
| /crates/core/machine/src/operations/fixed_rotate_right.rs | 87 |
| /crates/core/machine/src/operations/fixed_shift_right.rs | 91 |
| /crates/core/machine/src/operations/global_accumulation.rs | 176 |
| /crates/core/machine/src/operations/global_interaction.rs | 177 |
| /crates/core/machine/src/operations/is_equal_word.rs | 82 |
| /crates/core/machine/src/operations/is_zero.rs | 64 |
| /crates/core/machine/src/operations/is_zero_word.rs | 84 |
| /crates/core/machine/src/operations/mod.rs | 64 |
| /crates/core/machine/src/operations/msb.rs | 70 |
| /crates/core/machine/src/operations/mul.rs | 288 |
| /crates/core/machine/src/operations/not_u32.rs | 31 |
| /crates/core/machine/src/operations/page.rs | 267 |
| /crates/core/machine/src/operations/poseidon2/air.rs | 108 |
| /crates/core/machine/src/operations/poseidon2/mod.rs | 16 |
| /crates/core/machine/src/operations/poseidon2/permutation.rs | 81 |
| /crates/core/machine/src/operations/poseidon2/trace.rs | 101 |
| /crates/core/machine/src/operations/slt.rs | 233 |
| /crates/core/machine/src/operations/sp1_field_word.rs | 63 |
| /crates/core/machine/src/operations/sub.rs | 63 |
| /crates/core/machine/src/operations/subw.rs | 67 |
| /crates/core/machine/src/operations/syscall_addr.rs | 65 |
| /crates/core/machine/src/operations/u16_compare.rs | 69 |
| /crates/core/machine/src/operations/u16_operation.rs | 86 |
| /crates/core/machine/src/operations/u32_operation.rs | 29 |
| /crates/core/machine/src/operations/xor_u32.rs | 67 |
| /crates/core/machine/src/program/instruction.rs | 43 |
| /crates/core/machine/src/program/instruction_decode.rs | 536 |
| /crates/core/machine/src/program/instruction_fetch.rs | 280 |
| /crates/core/machine/src/program/mod.rs | 8 |
| /crates/core/machine/src/program/trusted.rs | 269 |
| /crates/core/machine/src/range/air.rs | 28 |
| /crates/core/machine/src/range/columns.rs | 15 |
| /crates/core/machine/src/range/mod.rs | 45 |
| /crates/core/machine/src/range/trace.rs | 73 |
| /crates/core/machine/src/riscv/mod.rs | 1097 |
| /crates/core/machine/src/syscall/chip.rs | 288 |
| /crates/core/machine/src/syscall/instructions/air.rs | 352 |
| /crates/core/machine/src/syscall/instructions/columns.rs | 29 |
| /crates/core/machine/src/syscall/instructions/mod.rs | 12 |
| /crates/core/machine/src/syscall/instructions/trace.rs | 130 |
| /crates/core/machine/src/syscall/mod.rs | 3 |
| /crates/core/machine/src/syscall/precompiles/edwards/ed_add.rs | 400 |
| /crates/core/machine/src/syscall/precompiles/edwards/ed_decompress.rs | 355 |
| /crates/core/machine/src/syscall/precompiles/edwards/mod.rs | 4 |
| /crates/core/machine/src/syscall/precompiles/fptower/fp.rs | 338 |
| /crates/core/machine/src/syscall/precompiles/fptower/fp2_addsub.rs | 375 |
| /crates/core/machine/src/syscall/precompiles/fptower/fp2_mul.rs | 419 |
| /crates/core/machine/src/syscall/precompiles/fptower/mod.rs | 58 |
| /crates/core/machine/src/syscall/precompiles/keccak256/air.rs | 199 |
| /crates/core/machine/src/syscall/precompiles/keccak256/columns.rs | 14 |
| /crates/core/machine/src/syscall/precompiles/keccak256/constants.rs | 151 |
| /crates/core/machine/src/syscall/precompiles/keccak256/controller.rs | 284 |
| /crates/core/machine/src/syscall/precompiles/keccak256/mod.rs | 33 |
| /crates/core/machine/src/syscall/precompiles/keccak256/trace.rs | 125 |
| /crates/core/machine/src/syscall/precompiles/mod.rs | 10 |
| /crates/core/machine/src/syscall/precompiles/mprotect/air.rs | 173 |
| /crates/core/machine/src/syscall/precompiles/mprotect/mod.rs | 2 |
| /crates/core/machine/src/syscall/precompiles/poseidon2/air.rs | 380 |
| /crates/core/machine/src/syscall/precompiles/poseidon2/mod.rs | 2 |
| /crates/core/machine/src/syscall/precompiles/sha256/compress/air.rs | 424 |
| /crates/core/machine/src/syscall/precompiles/sha256/compress/columns.rs | 65 |
| /crates/core/machine/src/syscall/precompiles/sha256/compress/controller.rs | 238 |
| /crates/core/machine/src/syscall/precompiles/sha256/compress/mod.rs | 40 |
| /crates/core/machine/src/syscall/precompiles/sha256/compress/trace.rs | 276 |
| /crates/core/machine/src/syscall/precompiles/sha256/extend/air.rs | 252 |
| /crates/core/machine/src/syscall/precompiles/sha256/extend/columns.rs | 41 |
| /crates/core/machine/src/syscall/precompiles/sha256/extend/controller.rs | 217 |
| /crates/core/machine/src/syscall/precompiles/sha256/extend/mod.rs | 45 |
| /crates/core/machine/src/syscall/precompiles/sha256/extend/trace.rs | 149 |
| /crates/core/machine/src/syscall/precompiles/sha256/mod.rs | 4 |
| /crates/core/machine/src/syscall/precompiles/u256x2048_mul/air.rs | 503 |
| /crates/core/machine/src/syscall/precompiles/u256x2048_mul/mod.rs | 18 |
| /crates/core/machine/src/syscall/precompiles/uint256/air.rs | 356 |
| /crates/core/machine/src/syscall/precompiles/uint256/mod.rs | 23 |
| /crates/core/machine/src/syscall/precompiles/uint256_ops/air.rs | 286 |
| /crates/core/machine/src/syscall/precompiles/uint256_ops/mod.rs | 238 |
| /crates/core/machine/src/syscall/precompiles/weierstrass/mod.rs | 6 |
| /crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_add.rs | 587 |
| /crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_decompress.rs | 611 |
| /crates/core/machine/src/syscall/precompiles/weierstrass/weierstrass_double.rs | 520 |
| /crates/core/machine/src/utils/concurrency.rs | 94 |
| /crates/core/machine/src/utils/logger.rs | 61 |
| /crates/core/machine/src/utils/mod.rs | 136 |
| /crates/core/machine/src/utils/span.rs | 99 |
| /crates/core/machine/src/utype/mod.rs | 182 |
| **Total** | **39411** |

### Files out of scope

_See [out_of_scope.txt](https://github.com/code-423n4/2025-09-succinct/blob/main/out_of_scope.txt)_

| File         |
| ------------ |
| ./crates/build/src/build.rs |
| ./crates/build/src/command/docker.rs |
| ./crates/build/src/command/local.rs |
| ./crates/build/src/command/mod.rs |
| ./crates/build/src/command/utils.rs |
| ./crates/build/src/lib.rs |
| ./crates/build/src/utils.rs |
| ./crates/cli/build.rs |
| ./crates/cli/src/bin/cargo-prove.rs |
| ./crates/cli/src/commands/build.rs |
| ./crates/cli/src/commands/install_toolchain.rs |
| ./crates/cli/src/commands/mod.rs |
| ./crates/cli/src/commands/new.rs |
| ./crates/cli/src/commands/vkey.rs |
| ./crates/cli/src/lib.rs |
| ./crates/core/compiler/src/ir/ast.rs |
| ./crates/core/compiler/src/ir/builder.rs |
| ./crates/core/compiler/src/main.rs |
| ./crates/core/executor/src/air.rs |
| ./crates/core/executor/src/context.rs |
| ./crates/core/executor/src/cost.rs |
| ./crates/core/executor/src/disassembler/elf.rs |
| ./crates/core/executor/src/disassembler/mod.rs |
| ./crates/core/executor/src/disassembler/rrs.rs |
| ./crates/core/executor/src/estimator.rs |
| ./crates/core/executor/src/events/byte.rs |
| ./crates/core/executor/src/events/global.rs |
| ./crates/core/executor/src/events/instr.rs |
| ./crates/core/executor/src/events/memory.rs |
| ./crates/core/executor/src/events/mod.rs |
| ./crates/core/executor/src/events/precompiles/ec.rs |
| ./crates/core/executor/src/events/precompiles/edwards.rs |
| ./crates/core/executor/src/events/precompiles/fptower.rs |
| ./crates/core/executor/src/events/precompiles/keccak256_permute.rs |
| ./crates/core/executor/src/events/precompiles/mod.rs |
| ./crates/core/executor/src/events/precompiles/mprotect.rs |
| ./crates/core/executor/src/events/precompiles/poseidon2.rs |
| ./crates/core/executor/src/events/precompiles/sha256_compress.rs |
| ./crates/core/executor/src/events/precompiles/sha256_extend.rs |
| ./crates/core/executor/src/events/precompiles/u256x2048_mul.rs |
| ./crates/core/executor/src/events/precompiles/uint256.rs |
| ./crates/core/executor/src/events/precompiles/uint256_ops.rs |
| ./crates/core/executor/src/events/syscall.rs |
| ./crates/core/executor/src/events/utils.rs |
| ./crates/core/executor/src/executor.rs |
| ./crates/core/executor/src/hook.rs |
| ./crates/core/executor/src/instruction.rs |
| ./crates/core/executor/src/io.rs |
| ./crates/core/executor/src/lib.rs |
| ./crates/core/executor/src/memory.rs |
| ./crates/core/executor/src/opcode.rs |
| ./crates/core/executor/src/opts.rs |
| ./crates/core/executor/src/profiler.rs |
| ./crates/core/executor/src/program.rs |
| ./crates/core/executor/src/recursion.rs |
| ./crates/core/executor/src/register.rs |
| ./crates/core/executor/src/report.rs |
| ./crates/core/executor/src/retain.rs |
| ./crates/core/executor/src/state.rs |
| ./crates/core/executor/src/subproof.rs |
| ./crates/core/executor/src/syscalls/code.rs |
| ./crates/core/executor/src/syscalls/commit.rs |
| ./crates/core/executor/src/syscalls/context.rs |
| ./crates/core/executor/src/syscalls/deferred.rs |
| ./crates/core/executor/src/syscalls/halt.rs |
| ./crates/core/executor/src/syscalls/hint.rs |
| ./crates/core/executor/src/syscalls/mod.rs |
| ./crates/core/executor/src/syscalls/mprotect.rs |
| ./crates/core/executor/src/syscalls/precompiles/edwards/add.rs |
| ./crates/core/executor/src/syscalls/precompiles/edwards/decompress.rs |
| ./crates/core/executor/src/syscalls/precompiles/edwards/mod.rs |
| ./crates/core/executor/src/syscalls/precompiles/fptower/fp.rs |
| ./crates/core/executor/src/syscalls/precompiles/fptower/fp2_addsub.rs |
| ./crates/core/executor/src/syscalls/precompiles/fptower/fp2_mul.rs |
| ./crates/core/executor/src/syscalls/precompiles/fptower/mod.rs |
| ./crates/core/executor/src/syscalls/precompiles/keccak256/mod.rs |
| ./crates/core/executor/src/syscalls/precompiles/keccak256/permute.rs |
| ./crates/core/executor/src/syscalls/precompiles/mod.rs |
| ./crates/core/executor/src/syscalls/precompiles/poseidon2.rs |
| ./crates/core/executor/src/syscalls/precompiles/sha256/compress.rs |
| ./crates/core/executor/src/syscalls/precompiles/sha256/extend.rs |
| ./crates/core/executor/src/syscalls/precompiles/sha256/mod.rs |
| ./crates/core/executor/src/syscalls/precompiles/u256x2048_mul.rs |
| ./crates/core/executor/src/syscalls/precompiles/uint256.rs |
| ./crates/core/executor/src/syscalls/precompiles/uint256_ops.rs |
| ./crates/core/executor/src/syscalls/precompiles/weierstrass/add.rs |
| ./crates/core/executor/src/syscalls/precompiles/weierstrass/decompress.rs |
| ./crates/core/executor/src/syscalls/precompiles/weierstrass/double.rs |
| ./crates/core/executor/src/syscalls/precompiles/weierstrass/mod.rs |
| ./crates/core/executor/src/syscalls/unconstrained.rs |
| ./crates/core/executor/src/syscalls/verify.rs |
| ./crates/core/executor/src/syscalls/write.rs |
| ./crates/core/executor/src/utils.rs |
| ./crates/core/machine/src/utils/prove.rs |
| ./crates/core/machine/src/utils/test.rs |
| ./crates/core/machine/src/utils/zerocheck_unit_test.rs |
| ./crates/cuda/src/api.rs |
| ./crates/cuda/src/client.rs |
| ./crates/cuda/src/error.rs |
| ./crates/cuda/src/lib.rs |
| ./crates/cuda/src/pk.rs |
| ./crates/cuda/src/server.rs |
| ./crates/curves/src/edwards/ed25519.rs |
| ./crates/curves/src/edwards/mod.rs |
| ./crates/curves/src/lib.rs |
| ./crates/curves/src/params.rs |
| ./crates/curves/src/polynomial.rs |
| ./crates/curves/src/scalar_mul.rs |
| ./crates/curves/src/uint256.rs |
| ./crates/curves/src/utils.rs |
| ./crates/curves/src/weierstrass/bls12_381.rs |
| ./crates/curves/src/weierstrass/bn254.rs |
| ./crates/curves/src/weierstrass/mod.rs |
| ./crates/curves/src/weierstrass/secp256k1.rs |
| ./crates/curves/src/weierstrass/secp256r1.rs |
| ./crates/derive/src/input_expr.rs |
| ./crates/derive/src/input_params.rs |
| ./crates/derive/src/into_shape.rs |
| ./crates/derive/src/lib.rs |
| ./crates/derive/src/sp1_operation_builder.rs |
| ./crates/eval/src/lib.rs |
| ./crates/eval/src/main.rs |
| ./crates/eval/src/program.rs |
| ./crates/helper/src/lib.rs |
| ./crates/hypercube/src/air/builder.rs |
| ./crates/hypercube/src/air/extension.rs |
| ./crates/hypercube/src/air/interaction.rs |
| ./crates/hypercube/src/air/machine.rs |
| ./crates/hypercube/src/air/mod.rs |
| ./crates/hypercube/src/air/public_values.rs |
| ./crates/hypercube/src/air/sub_builder.rs |
| ./crates/hypercube/src/chip.rs |
| ./crates/hypercube/src/debug.rs |
| ./crates/hypercube/src/folder.rs |
| ./crates/hypercube/src/ir/ast.rs |
| ./crates/hypercube/src/ir/compiler.rs |
| ./crates/hypercube/src/ir/conversions.rs |
| ./crates/hypercube/src/ir/expr.rs |
| ./crates/hypercube/src/ir/expr_impl.rs |
| ./crates/hypercube/src/ir/func.rs |
| ./crates/hypercube/src/ir/lean.rs |
| ./crates/hypercube/src/ir/mod.rs |
| ./crates/hypercube/src/ir/op.rs |
| ./crates/hypercube/src/ir/output.rs |
| ./crates/hypercube/src/ir/shape.rs |
| ./crates/hypercube/src/ir/var.rs |
| ./crates/hypercube/src/lib.rs |
| ./crates/hypercube/src/logup_gkr/cpu.rs |
| ./crates/hypercube/src/logup_gkr/execution.rs |
| ./crates/hypercube/src/logup_gkr/logup_poly.rs |
| ./crates/hypercube/src/logup_gkr/mod.rs |
| ./crates/hypercube/src/logup_gkr/proof.rs |
| ./crates/hypercube/src/logup_gkr/prover.rs |
| ./crates/hypercube/src/logup_gkr/verifier.rs |
| ./crates/hypercube/src/lookup/builder.rs |
| ./crates/hypercube/src/lookup/debug.rs |
| ./crates/hypercube/src/lookup/interaction.rs |
| ./crates/hypercube/src/lookup/mod.rs |
| ./crates/hypercube/src/machine.rs |
| ./crates/hypercube/src/prover/cpu.rs |
| ./crates/hypercube/src/prover/machine.rs |
| ./crates/hypercube/src/prover/memory_permit.rs |
| ./crates/hypercube/src/prover/mod.rs |
| ./crates/hypercube/src/prover/permits.rs |
| ./crates/hypercube/src/prover/shard.rs |
| ./crates/hypercube/src/prover/trace.rs |
| ./crates/hypercube/src/prover/zerocheck/fix_last_variable.rs |
| ./crates/hypercube/src/prover/zerocheck/mod.rs |
| ./crates/hypercube/src/prover/zerocheck/sum_as_poly.rs |
| ./crates/hypercube/src/record.rs |
| ./crates/hypercube/src/septic_curve.rs |
| ./crates/hypercube/src/septic_digest.rs |
| ./crates/hypercube/src/septic_extension.rs |
| ./crates/hypercube/src/shape/cluster.rs |
| ./crates/hypercube/src/shape/mod.rs |
| ./crates/hypercube/src/shape/ordered.rs |
| ./crates/hypercube/src/util.rs |
| ./crates/hypercube/src/verifier/config.rs |
| ./crates/hypercube/src/verifier/machine.rs |
| ./crates/hypercube/src/verifier/mod.rs |
| ./crates/hypercube/src/verifier/proof.rs |
| ./crates/hypercube/src/verifier/shard.rs |
| ./crates/hypercube/src/word.rs |
| ./crates/perf/src/executor.rs |
| ./crates/perf/src/main.rs |
| ./crates/primitives/src/consts.rs |
| ./crates/primitives/src/io.rs |
| ./crates/primitives/src/lib.rs |
| ./crates/primitives/src/polynomial.rs |
| ./crates/primitives/src/types.rs |
| ./crates/prover/build.rs |
| ./crates/prover/scripts/build_compress_vks.rs |
| ./crates/prover/scripts/build_groth16_bn254.rs |
| ./crates/prover/scripts/build_plonk_bn254.rs |
| ./crates/prover/scripts/build_recursion_vks.rs |
| ./crates/prover/scripts/fibonacci_groth16.rs |
| ./crates/prover/scripts/fibonacci_sweep.rs |
| ./crates/prover/scripts/find_maximal_shapes.rs |
| ./crates/prover/scripts/find_oom_shapes.rs |
| ./crates/prover/scripts/find_recursion_shape.rs |
| ./crates/prover/scripts/find_small_shapes.rs |
| ./crates/prover/scripts/post_trusted_setup.rs |
| ./crates/prover/scripts/tendermint_sweep.rs |
| ./crates/prover/scripts/test_shape_fixing.rs |
| ./crates/prover/src/build.rs |
| ./crates/prover/src/components.rs |
| ./crates/prover/src/core.rs |
| ./crates/prover/src/error.rs |
| ./crates/prover/src/gas/mod.rs |
| ./crates/prover/src/gas/model.rs |
| ./crates/prover/src/lib.rs |
| ./crates/prover/src/local.rs |
| ./crates/prover/src/recursion/components.rs |
| ./crates/prover/src/recursion.rs |
| ./crates/prover/src/shapes.rs |
| ./crates/prover/src/types.rs |
| ./crates/prover/src/utils.rs |
| ./crates/recursion/compiler/src/circuit/builder.rs |
| ./crates/recursion/compiler/src/circuit/compiler.rs |
| ./crates/recursion/compiler/src/circuit/config.rs |
| ./crates/recursion/compiler/src/circuit/mod.rs |
| ./crates/recursion/compiler/src/config.rs |
| ./crates/recursion/compiler/src/constraints/mod.rs |
| ./crates/recursion/compiler/src/constraints/opcodes.rs |
| ./crates/recursion/compiler/src/ir/arithmetic.rs |
| ./crates/recursion/compiler/src/ir/bits.rs |
| ./crates/recursion/compiler/src/ir/builder.rs |
| ./crates/recursion/compiler/src/ir/collections.rs |
| ./crates/recursion/compiler/src/ir/instructions.rs |
| ./crates/recursion/compiler/src/ir/iter.rs |
| ./crates/recursion/compiler/src/ir/mod.rs |
| ./crates/recursion/compiler/src/ir/poseidon.rs |
| ./crates/recursion/compiler/src/ir/ptr.rs |
| ./crates/recursion/compiler/src/ir/symbolic.rs |
| ./crates/recursion/compiler/src/ir/types.rs |
| ./crates/recursion/compiler/src/ir/utils.rs |
| ./crates/recursion/compiler/src/ir/var.rs |
| ./crates/recursion/compiler/src/lib.rs |
| ./crates/recursion/derive/src/lib.rs |
| ./crates/recursion/executor/src/analyzed.rs |
| ./crates/recursion/executor/src/block.rs |
| ./crates/recursion/executor/src/instruction.rs |
| ./crates/recursion/executor/src/lib.rs |
| ./crates/recursion/executor/src/memory.rs |
| ./crates/recursion/executor/src/opcode.rs |
| ./crates/recursion/executor/src/program.rs |
| ./crates/recursion/executor/src/public_values.rs |
| ./crates/recursion/executor/src/record.rs |
| ./crates/recursion/executor/src/shape.rs |
| ./crates/recursion/gnark-cli/src/main.rs |
| ./crates/recursion/gnark-ffi/build.rs |
| ./crates/recursion/gnark-ffi/go/main.go |
| ./crates/recursion/gnark-ffi/go/main_test.go |
| ./crates/recursion/gnark-ffi/go/sp1/build.go |
| ./crates/recursion/gnark-ffi/go/sp1/koalabear/koalabear.go |
| ./crates/recursion/gnark-ffi/go/sp1/poseidon2/constants.go |
| ./crates/recursion/gnark-ffi/go/sp1/poseidon2/poseidon2.go |
| ./crates/recursion/gnark-ffi/go/sp1/poseidon2/poseidon2_koalabear.go |
| ./crates/recursion/gnark-ffi/go/sp1/poseidon2/poseidon2_test.go |
| ./crates/recursion/gnark-ffi/go/sp1/poseidon2/utils.go |
| ./crates/recursion/gnark-ffi/go/sp1/prove.go |
| ./crates/recursion/gnark-ffi/go/sp1/sp1.go |
| ./crates/recursion/gnark-ffi/go/sp1/test.go |
| ./crates/recursion/gnark-ffi/go/sp1/trusted_setup/trusted_setup.go |
| ./crates/recursion/gnark-ffi/go/sp1/utils.go |
| ./crates/recursion/gnark-ffi/go/sp1/verify.go |
| ./crates/recursion/gnark-ffi/src/ffi/docker.rs |
| ./crates/recursion/gnark-ffi/src/ffi/mod.rs |
| ./crates/recursion/gnark-ffi/src/ffi/native.rs |
| ./crates/recursion/gnark-ffi/src/groth16_bn254.rs |
| ./crates/recursion/gnark-ffi/src/koalabear.rs |
| ./crates/recursion/gnark-ffi/src/lib.rs |
| ./crates/recursion/gnark-ffi/src/plonk_bn254.rs |
| ./crates/recursion/gnark-ffi/src/proof.rs |
| ./crates/recursion/gnark-ffi/src/witness.rs |
| ./crates/recursion/machine/src/chips/test_fixtures.rs |
| ./crates/recursion/machine/src/test.rs |
| ./crates/sdk/src/artifacts.rs |
| ./crates/sdk/src/client.rs |
| ./crates/sdk/src/cpu/builder.rs |
| ./crates/sdk/src/cpu/mod.rs |
| ./crates/sdk/src/cpu/prove.rs |
| ./crates/sdk/src/cuda/builder.rs |
| ./crates/sdk/src/cuda/mod.rs |
| ./crates/sdk/src/cuda/prove.rs |
| ./crates/sdk/src/env/mod.rs |
| ./crates/sdk/src/env/pk.rs |
| ./crates/sdk/src/env/prove.rs |
| ./crates/sdk/src/install.rs |
| ./crates/sdk/src/lib.rs |
| ./crates/sdk/src/mock.rs |
| ./crates/sdk/src/network/builder.rs |
| ./crates/sdk/src/network/client.rs |
| ./crates/sdk/src/network/error.rs |
| ./crates/sdk/src/network/grpc.rs |
| ./crates/sdk/src/network/mod.rs |
| ./crates/sdk/src/network/proto/artifact.rs |
| ./crates/sdk/src/network/proto/base/network.rs |
| ./crates/sdk/src/network/proto/base/types.rs |
| ./crates/sdk/src/network/proto/mod.rs |
| ./crates/sdk/src/network/proto/sepolia/network.rs |
| ./crates/sdk/src/network/proto/sepolia/types.rs |
| ./crates/sdk/src/network/prove.rs |
| ./crates/sdk/src/network/prover.rs |
| ./crates/sdk/src/network/retry.rs |
| ./crates/sdk/src/network/tee/api.rs |
| ./crates/sdk/src/network/tee/client.rs |
| ./crates/sdk/src/network/tee/mod.rs |
| ./crates/sdk/src/network/utils.rs |
| ./crates/sdk/src/proof.rs |
| ./crates/sdk/src/prover/execute.rs |
| ./crates/sdk/src/prover/prove.rs |
| ./crates/sdk/src/prover.rs |
| ./crates/sdk/src/utils.rs |
| ./crates/test-artifacts/build.rs |
| ./crates/test-artifacts/programs/bls12381-add/src/main.rs |
| ./crates/test-artifacts/programs/bls12381-decompress/src/main.rs |
| ./crates/test-artifacts/programs/bls12381-double/src/main.rs |
| ./crates/test-artifacts/programs/bls12381-fp/src/main.rs |
| ./crates/test-artifacts/programs/bls12381-fp2-addsub/src/main.rs |
| ./crates/test-artifacts/programs/bls12381-fp2-mul/src/main.rs |
| ./crates/test-artifacts/programs/bls12381-mul/src/main.rs |
| ./crates/test-artifacts/programs/bn254-add/src/main.rs |
| ./crates/test-artifacts/programs/bn254-double/src/main.rs |
| ./crates/test-artifacts/programs/bn254-fp/src/main.rs |
| ./crates/test-artifacts/programs/bn254-fp2-addsub/src/main.rs |
| ./crates/test-artifacts/programs/bn254-fp2-mul/src/main.rs |
| ./crates/test-artifacts/programs/bn254-mul/src/main.rs |
| ./crates/test-artifacts/programs/common/src/lib.rs |
| ./crates/test-artifacts/programs/common/src/weierstrass_add.rs |
| ./crates/test-artifacts/programs/cycle-tracker/src/main.rs |
| ./crates/test-artifacts/programs/ed-add/src/main.rs |
| ./crates/test-artifacts/programs/ed-decompress/src/main.rs |
| ./crates/test-artifacts/programs/ed25519/src/main.rs |
| ./crates/test-artifacts/programs/fibonacci/src/main.rs |
| ./crates/test-artifacts/programs/fibonacci-blake3/src/main.rs |
| ./crates/test-artifacts/programs/hello-world/src/main.rs |
| ./crates/test-artifacts/programs/hint-io/src/main.rs |
| ./crates/test-artifacts/programs/keccak-permute/src/main.rs |
| ./crates/test-artifacts/programs/keccak256/src/main.rs |
| ./crates/test-artifacts/programs/panic/src/main.rs |
| ./crates/test-artifacts/programs/rand/src/main.rs |
| ./crates/test-artifacts/programs/secp256k1-add/src/main.rs |
| ./crates/test-artifacts/programs/secp256k1-decompress/src/main.rs |
| ./crates/test-artifacts/programs/secp256k1-double/src/main.rs |
| ./crates/test-artifacts/programs/secp256k1-mul/src/main.rs |
| ./crates/test-artifacts/programs/secp256r1-add/src/main.rs |
| ./crates/test-artifacts/programs/secp256r1-decompress/src/main.rs |
| ./crates/test-artifacts/programs/secp256r1-double/src/main.rs |
| ./crates/test-artifacts/programs/sha-compress/src/main.rs |
| ./crates/test-artifacts/programs/sha-extend/src/main.rs |
| ./crates/test-artifacts/programs/sha2/src/main.rs |
| ./crates/test-artifacts/programs/ssz-withdrawals/src/beacon/hints.rs |
| ./crates/test-artifacts/programs/ssz-withdrawals/src/beacon/mod.rs |
| ./crates/test-artifacts/programs/ssz-withdrawals/src/beacon/prove.rs |
| ./crates/test-artifacts/programs/ssz-withdrawals/src/beacon/types.rs |
| ./crates/test-artifacts/programs/ssz-withdrawals/src/beacon/utils.rs |
| ./crates/test-artifacts/programs/ssz-withdrawals/src/main.rs |
| ./crates/test-artifacts/programs/tendermint-benchmark/src/main.rs |
| ./crates/test-artifacts/programs/u256x2048-mul/src/main.rs |
| ./crates/test-artifacts/programs/uint256-arith/src/main.rs |
| ./crates/test-artifacts/programs/uint256-mul/src/main.rs |
| ./crates/test-artifacts/programs/verify-proof/src/main.rs |
| ./crates/test-artifacts/src/lib.rs |
| ./crates/verifier/guest-verify-programs/src/groth16_verify.rs |
| ./crates/verifier/guest-verify-programs/src/plonk_verify.rs |
| ./crates/verifier/src/constants.rs |
| ./crates/verifier/src/converter.rs |
| ./crates/verifier/src/error.rs |
| ./crates/verifier/src/groth16/ark_converter.rs |
| ./crates/verifier/src/groth16/converter.rs |
| ./crates/verifier/src/groth16/error.rs |
| ./crates/verifier/src/groth16/mod.rs |
| ./crates/verifier/src/groth16/verify.rs |
| ./crates/verifier/src/lib.rs |
| ./crates/verifier/src/plonk/converter.rs |
| ./crates/verifier/src/plonk/error.rs |
| ./crates/verifier/src/plonk/hash_to_field.rs |
| ./crates/verifier/src/plonk/kzg.rs |
| ./crates/verifier/src/plonk/mod.rs |
| ./crates/verifier/src/plonk/proof.rs |
| ./crates/verifier/src/plonk/transcript.rs |
| ./crates/verifier/src/plonk/verify.rs |
| ./crates/verifier/src/tests.rs |
| ./crates/verifier/src/utils.rs |
| ./crates/zkvm/entrypoint/src/allocators/bump.rs |
| ./crates/zkvm/entrypoint/src/allocators/embedded.rs |
| ./crates/zkvm/entrypoint/src/allocators/mod.rs |
| ./crates/zkvm/entrypoint/src/lib.rs |
| ./crates/zkvm/entrypoint/src/libm.rs |
| ./crates/zkvm/entrypoint/src/syscalls/bigint.rs |
| ./crates/zkvm/entrypoint/src/syscalls/bls12381.rs |
| ./crates/zkvm/entrypoint/src/syscalls/bn254.rs |
| ./crates/zkvm/entrypoint/src/syscalls/ed25519.rs |
| ./crates/zkvm/entrypoint/src/syscalls/fptower.rs |
| ./crates/zkvm/entrypoint/src/syscalls/halt.rs |
| ./crates/zkvm/entrypoint/src/syscalls/io.rs |
| ./crates/zkvm/entrypoint/src/syscalls/keccak_permute.rs |
| ./crates/zkvm/entrypoint/src/syscalls/memory.rs |
| ./crates/zkvm/entrypoint/src/syscalls/mod.rs |
| ./crates/zkvm/entrypoint/src/syscalls/mprotect.rs |
| ./crates/zkvm/entrypoint/src/syscalls/poseidon2.rs |
| ./crates/zkvm/entrypoint/src/syscalls/secp256k1.rs |
| ./crates/zkvm/entrypoint/src/syscalls/secp256r1.rs |
| ./crates/zkvm/entrypoint/src/syscalls/sha_compress.rs |
| ./crates/zkvm/entrypoint/src/syscalls/sha_extend.rs |
| ./crates/zkvm/entrypoint/src/syscalls/sys.rs |
| ./crates/zkvm/entrypoint/src/syscalls/u256x2048_mul.rs |
| ./crates/zkvm/entrypoint/src/syscalls/uint256_mul.rs |
| ./crates/zkvm/entrypoint/src/syscalls/uint256_ops.rs |
| ./crates/zkvm/entrypoint/src/syscalls/unconstrained.rs |
| ./crates/zkvm/entrypoint/src/syscalls/verify.rs |
| ./crates/zkvm/lib/src/bls12381.rs |
| ./crates/zkvm/lib/src/bn254.rs |
| ./crates/zkvm/lib/src/ecdsa/affine.rs |
| ./crates/zkvm/lib/src/ecdsa/projective.rs |
| ./crates/zkvm/lib/src/ecdsa.rs |
| ./crates/zkvm/lib/src/ed25519.rs |
| ./crates/zkvm/lib/src/io.rs |
| ./crates/zkvm/lib/src/lib.rs |
| ./crates/zkvm/lib/src/mprotect.rs |
| ./crates/zkvm/lib/src/secp256k1.rs |
| ./crates/zkvm/lib/src/secp256r1.rs |
| ./crates/zkvm/lib/src/unconstrained.rs |
| ./crates/zkvm/lib/src/utils.rs |
| ./crates/zkvm/lib/src/verify.rs |
| ./examples/aggregation/program/src/main.rs |
| ./examples/aggregation/script/build.rs |
| ./examples/aggregation/script/src/main.rs |
| ./examples/bls12381/program/src/main.rs |
| ./examples/bls12381/script/build.rs |
| ./examples/bls12381/script/src/main.rs |
| ./examples/bn254/program/src/main.rs |
| ./examples/bn254/script/build.rs |
| ./examples/bn254/script/src/main.rs |
| ./examples/chess/program/src/main.rs |
| ./examples/chess/script/build.rs |
| ./examples/chess/script/src/main.rs |
| ./examples/cycle-tracking/program/bin/normal.rs |
| ./examples/cycle-tracking/program/bin/report.rs |
| ./examples/cycle-tracking/script/build.rs |
| ./examples/cycle-tracking/script/src/main.rs |
| ./examples/ed-add/program/src/main.rs |
| ./examples/ed-add/script/build.rs |
| ./examples/ed-add/script/src/main.rs |
| ./examples/fibonacci/program/src/main.rs |
| ./examples/fibonacci/script/bin/compressed.rs |
| ./examples/fibonacci/script/bin/core_u64.rs |
| ./examples/fibonacci/script/bin/execute.rs |
| ./examples/fibonacci/script/bin/groth16_bn254.rs |
| ./examples/fibonacci/script/bin/network.rs |
| ./examples/fibonacci/script/bin/plonk_bn254.rs |
| ./examples/fibonacci/script/build.rs |
| ./examples/fibonacci/script/src/main.rs |
| ./examples/fibonacci-cuda/program/src/main.rs |
| ./examples/fibonacci-cuda/script/build.rs |
| ./examples/fibonacci-cuda/script/src/main.rs |
| ./examples/fp2/program/src/main.rs |
| ./examples/fp2/script/build.rs |
| ./examples/fp2/script/src/main.rs |
| ./examples/fptower/program/src/main.rs |
| ./examples/fptower/script/build.rs |
| ./examples/fptower/script/src/main.rs |
| ./examples/groth16/program/src/main.rs |
| ./examples/groth16/script/build.rs |
| ./examples/groth16/script/src/main.rs |
| ./examples/io/program/src/main.rs |
| ./examples/io/script/build.rs |
| ./examples/io/script/src/main.rs |
| ./examples/is-prime/program/src/main.rs |
| ./examples/is-prime/script/build.rs |
| ./examples/is-prime/script/src/main.rs |
| ./examples/json/lib/src/lib.rs |
| ./examples/json/program/src/main.rs |
| ./examples/json/script/build.rs |
| ./examples/json/script/src/main.rs |
| ./examples/keccak/program/src/main.rs |
| ./examples/keccak/script/build.rs |
| ./examples/keccak/script/src/main.rs |
| ./examples/mprotect/program/src/main.rs |
| ./examples/mprotect/script/bin/core_u64.rs |
| ./examples/mprotect/script/build.rs |
| ./examples/mprotect/script/src/main.rs |
| ./examples/poseidon2/program/src/main.rs |
| ./examples/poseidon2/script/build.rs |
| ./examples/poseidon2/script/src/main.rs |
| ./examples/regex/program/src/main.rs |
| ./examples/regex/script/build.rs |
| ./examples/regex/script/src/main.rs |
| ./examples/rsa/program/src/main.rs |
| ./examples/rsa/script/build.rs |
| ./examples/rsa/script/src/main.rs |
| ./examples/rsp/program/src/main.rs |
| ./examples/rsp/script/bin/core_u64.rs |
| ./examples/rsp/script/build.rs |
| ./examples/rsp/script/src/main.rs |
| ./examples/secp256k1/program/src/main.rs |
| ./examples/secp256k1/script/build.rs |
| ./examples/secp256k1/script/src/main.rs |
| ./examples/sha/program/src/main.rs |
| ./examples/sha/script/build.rs |
| ./examples/sha/script/src/main.rs |
| ./examples/ssz-withdrawals/program/src/beacon/hints.rs |
| ./examples/ssz-withdrawals/program/src/beacon/mod.rs |
| ./examples/ssz-withdrawals/program/src/beacon/prove.rs |
| ./examples/ssz-withdrawals/program/src/beacon/types.rs |
| ./examples/ssz-withdrawals/program/src/beacon/utils.rs |
| ./examples/ssz-withdrawals/program/src/main.rs |
| ./examples/ssz-withdrawals/script/bin/core_u64.rs |
| ./examples/ssz-withdrawals/script/build.rs |
| ./examples/ssz-withdrawals/script/src/main.rs |
| ./examples/tendermint/program/src/main.rs |
| ./examples/tendermint/script/bin/core_u64.rs |
| ./examples/tendermint/script/build.rs |
| ./examples/tendermint/script/src/lib.rs |
| ./examples/tendermint/script/src/main.rs |
| ./examples/tendermint/script/src/util.rs |
| ./examples/u256x2048-mul/program/src/main.rs |
| ./examples/u256x2048-mul/script/build.rs |
| ./examples/u256x2048-mul/script/src/main.rs |
| ./examples/uint256/program/src/main.rs |
| ./examples/uint256/script/build.rs |
| ./examples/uint256/script/src/main.rs |
| ./examples/untrusted_program/jit-program/src/lui_example.rs |
| ./examples/untrusted_program/jit-program/src/main.rs |
| ./examples/untrusted_program/jit-program/src/seven_instruction_example.rs |
| ./examples/untrusted_program/program/src/main.rs |
| ./examples/untrusted_program/script/build.rs |
| ./examples/untrusted_program/script/src/main.rs |
| ./patch-testing/RustCrypto-rsa/build.rs |
| ./patch-testing/RustCrypto-rsa/program/bin/verify_pkcs.rs |
| ./patch-testing/RustCrypto-rsa/src/lib.rs |
| ./patch-testing/bls12-381/build.rs |
| ./patch-testing/bls12-381/program/bin/test_bls_add.rs |
| ./patch-testing/bls12-381/program/bin/test_bls_double.rs |
| ./patch-testing/bls12-381/program/bin/test_inverse.rs |
| ./patch-testing/bls12-381/program/bin/test_inverse_fp2.rs |
| ./patch-testing/bls12-381/program/bin/test_sqrt.rs |
| ./patch-testing/bls12-381/program/bin/test_sqrt_fp2.rs |
| ./patch-testing/bls12-381/src/lib.rs |
| ./patch-testing/bn/build.rs |
| ./patch-testing/bn/program/bin/test_fq_inverse.rs |
| ./patch-testing/bn/program/bin/test_fq_sqrt.rs |
| ./patch-testing/bn/program/bin/test_fr_inverse.rs |
| ./patch-testing/bn/program/bin/test_g1_add.rs |
| ./patch-testing/bn/program/bin/test_g1_double.rs |
| ./patch-testing/bn/src/lib.rs |
| ./patch-testing/build-host/src/main.rs |
| ./patch-testing/curve25519-dalek/build.rs |
| ./patch-testing/curve25519-dalek/program/bin/add_then_multiply.rs |
| ./patch-testing/curve25519-dalek/program/bin/decompress.rs |
| ./patch-testing/curve25519-dalek/program/bin/verify.rs |
| ./patch-testing/curve25519-dalek/program/bin/zero_msm.rs |
| ./patch-testing/curve25519-dalek/program/bin/zero_mul.rs |
| ./patch-testing/curve25519-dalek/src/lib.rs |
| ./patch-testing/curve25519-dalek-ng/build.rs |
| ./patch-testing/curve25519-dalek-ng/program/bin/add_then_multiply.rs |
| ./patch-testing/curve25519-dalek-ng/program/bin/decompress.rs |
| ./patch-testing/curve25519-dalek-ng/program/bin/zero_msm.rs |
| ./patch-testing/curve25519-dalek-ng/program/bin/zero_mul.rs |
| ./patch-testing/curve25519-dalek-ng/src/lib.rs |
| ./patch-testing/k256/build.rs |
| ./patch-testing/k256/program/bin/recover.rs |
| ./patch-testing/k256/program/bin/schnorr_verify.rs |
| ./patch-testing/k256/program/bin/verify.rs |
| ./patch-testing/k256/src/lib.rs |
| ./patch-testing/keccak/build.rs |
| ./patch-testing/keccak/program/src/main.rs |
| ./patch-testing/keccak/src/lib.rs |
| ./patch-testing/p256/build.rs |
| ./patch-testing/p256/program/bin/recover.rs |
| ./patch-testing/p256/program/bin/verify.rs |
| ./patch-testing/p256/src/lib.rs |
| ./patch-testing/rustcrypto-bigint/build.rs |
| ./patch-testing/rustcrypto-bigint/program/bin/mul_add_residue.rs |
| ./patch-testing/rustcrypto-bigint/program/bin/mul_mod_special.rs |
| ./patch-testing/rustcrypto-bigint/src/lib.rs |
| ./patch-testing/secp256k1/build.rs |
| ./patch-testing/secp256k1/program-v0.29.1/bin/recover.rs |
| ./patch-testing/secp256k1/program-v0.29.1/bin/verify.rs |
| ./patch-testing/secp256k1/program-v0.30.0/bin/recover.rs |
| ./patch-testing/secp256k1/program-v0.30.0/bin/verify.rs |
| ./patch-testing/secp256k1/src/lib.rs |
| ./patch-testing/sha/build.rs |
| ./patch-testing/sha/program/bin/sha2.rs |
| ./patch-testing/sha/program/bin/sha3.rs |
| ./patch-testing/sha/src/lib.rs |
| ./patch-testing/sp1-test/bin/post_to_github.rs |
| ./patch-testing/sp1-test/src/lib.rs |
| ./patch-testing/sp1-test/src/utils.rs |
| ./patch-testing/sp1-test-macro/src/attr.rs |
| ./patch-testing/sp1-test-macro/src/lib.rs |
| ./slop/crates/adapter-prover/src/lib.rs |
| ./slop/crates/air/src/lib.rs |
| ./slop/crates/algebra/src/lib.rs |
| ./slop/crates/algebra/src/univariate.rs |
| ./slop/crates/alloc/src/allocator.rs |
| ./slop/crates/alloc/src/backend/cpu.rs |
| ./slop/crates/alloc/src/backend/io.rs |
| ./slop/crates/alloc/src/backend/mod.rs |
| ./slop/crates/alloc/src/backend_challenger.rs |
| ./slop/crates/alloc/src/buffer.rs |
| ./slop/crates/alloc/src/init.rs |
| ./slop/crates/alloc/src/lib.rs |
| ./slop/crates/alloc/src/mem.rs |
| ./slop/crates/alloc/src/raw_buffer.rs |
| ./slop/crates/alloc/src/slice.rs |
| ./slop/crates/baby-bear/src/baby_bear_poseidon2.rs |
| ./slop/crates/baby-bear/src/lib.rs |
| ./slop/crates/basefold/src/code.rs |
| ./slop/crates/basefold/src/config.rs |
| ./slop/crates/basefold/src/lib.rs |
| ./slop/crates/basefold/src/verifier.rs |
| ./slop/crates/basefold-prover/src/configs.rs |
| ./slop/crates/basefold-prover/src/encoder.rs |
| ./slop/crates/basefold-prover/src/fri.rs |
| ./slop/crates/basefold-prover/src/lib.rs |
| ./slop/crates/basefold-prover/src/pow.rs |
| ./slop/crates/basefold-prover/src/prover.rs |
| ./slop/crates/bn254/src/lib.rs |
| ./slop/crates/challenger/src/lib.rs |
| ./slop/crates/challenger/src/synchronize.rs |
| ./slop/crates/commit/src/lib.rs |
| ./slop/crates/commit/src/message.rs |
| ./slop/crates/commit/src/rounds.rs |
| ./slop/crates/dft/src/lib.rs |
| ./slop/crates/dft/src/p3.rs |
| ./slop/crates/fri/src/lib.rs |
| ./slop/crates/futures/src/handle.rs |
| ./slop/crates/futures/src/lib.rs |
| ./slop/crates/futures/src/queue.rs |
| ./slop/crates/futures/src/rayon.rs |
| ./slop/crates/futures/src/scope.rs |
| ./slop/crates/futures/src/values.rs |
| ./slop/crates/jagged/src/basefold.rs |
| ./slop/crates/jagged/src/config.rs |
| ./slop/crates/jagged/src/hadamard.rs |
| ./slop/crates/jagged/src/jagged_eval/eval_sumcheck_prover.rs |
| ./slop/crates/jagged/src/jagged_eval/mod.rs |
| ./slop/crates/jagged/src/jagged_eval/sumcheck_eval.rs |
| ./slop/crates/jagged/src/jagged_eval/sumcheck_poly.rs |
| ./slop/crates/jagged/src/jagged_eval/sumcheck_sum_as_poly.rs |
| ./slop/crates/jagged/src/lib.rs |
| ./slop/crates/jagged/src/long.rs |
| ./slop/crates/jagged/src/multi_to_uni.rs |
| ./slop/crates/jagged/src/poly.rs |
| ./slop/crates/jagged/src/populate.rs |
| ./slop/crates/jagged/src/prover.rs |
| ./slop/crates/jagged/src/sumcheck.rs |
| ./slop/crates/jagged/src/verifier.rs |
| ./slop/crates/keccak-air/src/lib.rs |
| ./slop/crates/koala-bear/src/koala_bear_poseidon2.rs |
| ./slop/crates/koala-bear/src/lib.rs |
| ./slop/crates/matrix/src/lib.rs |
| ./slop/crates/maybe-rayon/src/lib.rs |
| ./slop/crates/merkle-tree/src/bn254fr_poseidon2.rs |
| ./slop/crates/merkle-tree/src/lib.rs |
| ./slop/crates/merkle-tree/src/p3.rs |
| ./slop/crates/merkle-tree/src/tcs.rs |
| ./slop/crates/multilinear/src/base.rs |
| ./slop/crates/multilinear/src/eval.rs |
| ./slop/crates/multilinear/src/fold.rs |
| ./slop/crates/multilinear/src/lagrange.rs |
| ./slop/crates/multilinear/src/lib.rs |
| ./slop/crates/multilinear/src/mle.rs |
| ./slop/crates/multilinear/src/padded.rs |
| ./slop/crates/multilinear/src/pcs.rs |
| ./slop/crates/multilinear/src/point.rs |
| ./slop/crates/multilinear/src/restrict.rs |
| ./slop/crates/multilinear/src/virtual_geq.rs |
| ./slop/crates/multivariate-adapter/src/air_types.rs |
| ./slop/crates/multivariate-adapter/src/folder.rs |
| ./slop/crates/multivariate-adapter/src/lib.rs |
| ./slop/crates/multivariate-adapter/src/types.rs |
| ./slop/crates/multivariate-adapter/src/verifier.rs |
| ./slop/crates/pcs-bench/src/lib.rs |
| ./slop/crates/pgspcs/src/lib.rs |
| ./slop/crates/pgspcs/src/prover.rs |
| ./slop/crates/pgspcs/src/sparse_poly.rs |
| ./slop/crates/pgspcs/src/sumcheck_polynomials.rs |
| ./slop/crates/pgspcs/src/utils.rs |
| ./slop/crates/pgspcs/src/verifier.rs |
| ./slop/crates/poseidon2/src/lib.rs |
| ./slop/crates/slop/src/lib.rs |
| ./slop/crates/spartan/src/batched_lincheck_poly.rs |
| ./slop/crates/spartan/src/lib.rs |
| ./slop/crates/spartan/src/lincheck_poly.rs |
| ./slop/crates/spartan/src/prodcheck_poly.rs |
| ./slop/crates/spartan/src/proof.rs |
| ./slop/crates/spartan/src/prover.rs |
| ./slop/crates/spartan/src/r1cs.rs |
| ./slop/crates/spartan/src/sparse_matrix.rs |
| ./slop/crates/spartan/src/verifier.rs |
| ./slop/crates/stacked/src/fixed_rate.rs |
| ./slop/crates/stacked/src/greedy.rs |
| ./slop/crates/stacked/src/interleave.rs |
| ./slop/crates/stacked/src/lib.rs |
| ./slop/crates/stacked/src/prover.rs |
| ./slop/crates/stacked/src/verifier.rs |
| ./slop/crates/sumcheck/src/backend.rs |
| ./slop/crates/sumcheck/src/lib.rs |
| ./slop/crates/sumcheck/src/mle.rs |
| ./slop/crates/sumcheck/src/poly.rs |
| ./slop/crates/sumcheck/src/proof.rs |
| ./slop/crates/sumcheck/src/prover.rs |
| ./slop/crates/sumcheck/src/verifier.rs |
| ./slop/crates/symmetric/src/lib.rs |
| ./slop/crates/tensor/src/dimensions.rs |
| ./slop/crates/tensor/src/dot.rs |
| ./slop/crates/tensor/src/inner.rs |
| ./slop/crates/tensor/src/lib.rs |
| ./slop/crates/tensor/src/reduce.rs |
| ./slop/crates/tensor/src/sum.rs |
| ./slop/crates/tensor/src/transpose.rs |
| ./slop/crates/uni-stark/src/lib.rs |
| ./slop/crates/utils/src/lib.rs |
| ./slop/crates/utils/src/logger.rs |
| ./slop/crates/whir/src/config.rs |
| ./slop/crates/whir/src/lib.rs |
| ./slop/crates/whir/src/prover.rs |
| ./slop/crates/whir/src/verifier.rs |
| Totals: 721 |

# Additional context

## Areas of concern (where to focus for bugs)

- A valid execution being unprovable (i.e. completeness issues), where the ELF at hand is derived from the given SP1 toolchain with a memory safe Rust program.
- An invalid execution being provable (i.e. soundness issues).

## Main invariants

These invariants hold inductively throughout the proof.

- All memory states and registers states are `u64` of four `u16` limbs.
- The `clk_high, clk_low` values at each RISC-V instruction chip and precompile chips, as well as initial & final states of a shard are valid 24-bit values.
- The `clk` value (which is `clk_low + clk_high * 2^24`) is always `1 (mod 8)`.
- The timestamp values used for register/memory/permissions access arguments are always two valid 24-bit limbs. The `pc` values are always three valid 16-bit limbs.
- All interactions that do not come from a "trusted source" (either from a preprocessed trace, or other main trace that is entirely constrained to be correct, i.e. `ProgramChip`, `ByteChip`, `RangeChip`, `InstructionDecodeChip`) have boolean multiplicity always.
- `x0` is hard-wired to zero.

These are assumptions you can make about the user program.

- The user program ends with a call to the `syscall_halt` function.

## All trusted roles in the protocol

N/A

## Running tests

```bash
git clone  https://github.com/code-423n4/2025-09-succinct.git
# Install toolchain from repo
cargo run -p sp1-cli --no-default-features -- prove install-toolchain
# Run test
cargo test --release --workspace --exclude sp1-verifier --exclude sp1-sdk --features native-gnark --features unsound
```

## Miscellaneous

Employees of Succinct Labs and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.
