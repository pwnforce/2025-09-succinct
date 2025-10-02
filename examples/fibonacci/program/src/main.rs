//! A simple program that takes a number `n` as input, and writes the `n-1`th and `n`th fibonacci
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

#![no_std]
#![no_main]
#![feature(global_asm)] // Required for global_asm! on stable Rust; omit if using nightly

use core::arch::global_asm;

global_asm!(
    r#"
.align 4
    .type run_asm_test, @function
run_asm_test:           
                  li x5, 0
                  li x6, 0
                  beq x5, x6, 0f
0: la x31, h0_start
jalr x0, x31, 0
h0_start:
init:             
                  li x0, 0x4
                  li x1, 0x0
                  li x2, 0x80000000
                  li x3, 0xe6c59845
                  li x4, 0x0
                  li x5, 0x0
                  li x6, 0xfae64783
                  li x7, 0x80000000
                  li x8, 0x1c1d4ec8
                  li x9, 0x80000000
                  li x11, 0xab226295
                  li x12, 0x46ed09f3
                  li x13, 0x9
                  li x14, 0x80000000
                  li x16, 0x80000000
                  li x17, 0x0
                  li x18, 0xfadd9d0d
                  li x19, 0x5
                  li x20, 0xf013c5ec
                  li x21, 0x7f79d3c
                  li x22, 0xb6900ade
                  li x23, 0xd
                  li x24, 0x80000000
                  li x25, 0xb
                  li x26, 0xc
                  li x27, 0xf195f286
                  li x28, 0x80000000
                  li x29, 0xf7161361
                  li x30, 0x80000000
                  li x31, 0xf33888df
                  la x15, user_stack_end
             slli        t5, s9, 31
                  blt         t3, t6, 6f
                  sll         s8, t2, t6
                  bltu        a2, s2, 9f
                  divw        a7, a5, s9
                  addw        s5, s3, t6
6:                bne         s0, s7, 11f
                  lui         t3, 93431
                  addw        t5, a5, s7
9:                and         s6, s0, tp
                  bgeu        a3, s2, 15f
11:               sltiu       a4, a4, -1983
                  lui         zero, 1019453
                  sltiu       t5, s6, 1532
                  slli        s0, tp, 20
15:               bgeu        sp, a4, 34f
                  beq         t2, t6, 24f
                  sub         a1, a3, t4
                  divuw       s3, s0, s0
                  bge         t2, sp, 27f
                  sraw        t1, t6, ra
                  add         t3, t1, s10
                  divw        s6, zero, s9
                  subw        s9, s8, a0
24:               mulhsu      sp, zero, t1
                  remuw       tp, s8, t2
                  srai        a6, zero, 4
27:               bltu        tp, a5, 37f
                  subw        zero, s0, a4
                  remw        s4, sp, t1
                  srliw       a7, s8, 1
                  rem         s1, a1, s8
                  divuw       t4, s1, t0
                  mul         ra, gp, ra
34:               sraiw       t5, t5, 29
                  sub         a7, t4, t1
                  xor         s1, a1, t0
37:               beq         s9, s10, 42f
                  rem         s6, a5, s3
                  andi        a4, t6, 1773
                  mulhu       s1, t2, s11
                  and         s6, a6, a1
42:               divu        a1, s0, s2
                  lui         s9, 572277
                  div         zero, ra, s3
                  auipc       a4, 860368
                  mulw        t3, s8, zero
                  sllw        a4, s10, t1
                  bltu        t5, sp, 58f
                  add         s0, tp, a2
                  auipc       s3, 736210
                  sraiw       t4, tp, 4
                  divw        tp, s8, gp
                  addi        s2, s4, 484
                  xori        s6, ra, 1848
                  sltu        s6, s10, a6
                  remuw       a2, a5, a4
                  mulh        s7, s3, ra
58:               srlw        s5, t0, s2
                  ori         gp, a7, 1902
                  sraw        a1, sp, s1
                  blt         a2, a4, 69f
                  mul         s5, a5, t6
                  sub         t2, a7, s7
                  andi        s4, s6, -1797
                  add         s1, s0, a2
                  sub         t1, s4, t5
                  mul         t0, t1, a2
                  mul         zero, a0, s1
69:               bge         t4, a7, 72f
                  sllw        t0, gp, s8
                  andi        s2, t0, -2002
72:               nop
                  slt         gp, a3, s5
                  divuw       t4, a4, s8
                  sraw        s1, a3, t6
                  add         gp, s5, s10
                  blt         s8, t0, 79f
                  mulhsu      a1, s11, a2
79:               lui         s8, 730275
                  sllw        zero, s10, s10
                  auipc       sp, 436341
                  slli        s1, t0, 30
                  bge         s10, a7, 101f
                  mulhsu      s4, a2, t1
                  ori         ra, a1, 446
                  sraiw       t0, tp, 22
                  sra         ra, s11, s11
                  or          s7, s4, a6
                  addiw       t1, a3, -2016
                  remuw       t5, t5, sp
                  sltiu       ra, zero, -860
                  and         s4, t4, s8
                  srlw        t3, s3, s10
                  sllw        s2, t0, a3
                  bltu        t6, t6, 114f
                  srl         t4, s8, a1
                  slti        zero, a0, 1395
                  mulhsu      t4, a3, s6
                  xori        s8, s5, 1467
                  divu        s10, t4, tp
101:              divuw       s5, a3, s0
                  sub         gp, a6, a6
                  sraw        s8, s6, a4
                  or          t5, gp, s2
                  sub         a7, t0, a0
                  mulhsu      s9, a0, a5
                  or          s4, s6, a2
                  div         t5, s8, t2
                  blt         t4, a5, 110f
110:              sltu        s7, t6, s7
                  blt         t1, gp, 131f
                  add         s4, a5, t6
                  add         a2, a2, a0
114:              andi        ra, a7, -522
                  add         ra, a1, a1
                  sra         s1, t5, t1
                  addiw       s6, zero, 388
                  mulhsu      a4, t5, s11
                  lui         s4, 341690
                  xori        s10, t4, -952
                  div         a6, a6, s9
                  sll         zero, tp, s2
                  lui         zero, 1046586
                  bne         t2, s0, 140f
                  addiw       a3, a5, 1436
                  bltu        t4, s3, 135f
                  subw        zero, t2, s5
                  lui         a7, 643749
                  nop
                  addiw       zero, tp, -142
131:              addi        zero, s9, -944
                  or          a7, sp, sp
                  sll         zero, zero, s7
                  nop
135:              div         s0, s5, zero
                  divu        s8, s3, t3
                  srlw        s7, s9, s8
                  srli        sp, s3, 49
                  blt         a3, t0, 140f
140:              sltiu       a3, s9, -839
                  bltu        s1, t0, 158f
                  sll         ra, t1, s9
                  slli        s7, a2, 49
                  bge         a3, s3, 159f
                  sub         s0, a5, a5
                  mul         a6, s11, zero
                  mul         s0, a2, s1
                  blt         s0, a0, 166f
                  sub         a3, a7, gp
                  nop
                  srai        s9, s1, 29
                  add         zero, ra, sp
                  rem         s0, a7, s6
                  xor         s1, s1, a3
                  mulw        ra, a0, s1
                  sub         s7, zero, t3
                  mulhsu      s0, t4, s2
158:              sraiw       s7, a1, 26
159:              subw        s0, t4, sp
                  mul         t1, s3, s9
                  blt         tp, a0, 168f
                  auipc       a6, 257519
                  remuw       zero, t0, s1
                  bgeu        a5, t0, 179f
                  slt         s2, s9, s5
166:              remuw       tp, a0, s0
                  sra         s9, gp, t2
168:              addw        s6, s4, s8
                  bge         s11, s8, 170f
170:              sraw        sp, a5, s7
                  sraiw       s2, s0, 29
                  addiw       t3, s0, 209
                  divu        a7, s2, s9
                  sll         s6, sp, a3
                  xori        zero, t2, 610
                  div         a2, a2, s7
                  srlw        a7, sp, a7
                  slt         zero, t0, a7
179:              remw        s10, t4, s1
                  srli        s9, a1, 53
                  addw        s7, tp, s0
                  srli        a6, s9, 18
                  sub         s7, t1, s0
                  xori        a2, s5, 615
                  and         zero, s5, ra
                  addw        s7, t6, a0
                  and         s7, a6, a0
                  slliw       a4, t3, 4
                  sub         ra, a6, gp
                  xor         t1, s1, zero
                  srai        a7, s4, 11
                  sraiw       t1, s11, 30
                  srlw        a1, s9, a6
                  srlw        t1, t6, s3
                  add         s11, sp, s9
                  slti        a6, s2, 2026
                  xori        a6, s5, 345
                  remuw       t2, t0, s9
                  divuw       a1, s11, t1
                  bltu        a6, s9, 206f
                  beq         s2, s6, 204f
                  sltiu       tp, t0, -1355
                  divw        t2, s3, t5
204:              bltu        s4, a6, 215f
                  sraiw       t3, gp, 4
206:              andi        s11, s8, -544
                  sltiu       s9, a4, 564
                  lui         t5, 510190
                  divuw       t1, a4, s4
                  slt         s7, s2, s5
                  sra         t1, gp, s9
                  andi        s7, s3, 478
                  sub         s4, a5, s6
                  sraw        t5, s7, sp
215:              slliw       s0, s4, 0
                  mulh        zero, gp, s8
                  divuw       t2, t4, t3
                  srlw        s2, s4, t5
                  mulhsu      tp, a3, a7
                  srl         t1, s4, a4
                  addw        tp, s4, a4
                  sub         s1, s11, s6
                  mulhsu      gp, s10, sp
                  sltu        t5, s10, s1
                  bne         s8, s9, 234f
                  sll         s1, gp, s4
                  sltiu       s11, a3, -686
                  auipc       t0, 410546
                  slti        s1, s4, -389
                  bne         s9, s3, 231f
231:              sltiu       t0, t4, -1931
                  lui         s5, 177602
                  remw        a3, ra, s4
234:              remuw       s4, a1, a1
                  bge         s2, a6, 253f
                  andi        ra, s3, -1331
                  blt         zero, t6, 255f
                  or          s2, a2, s8
                  bltu        zero, gp, 244f
                  mulw        a4, zero, zero
                  remuw       a6, a6, ra
                  blt         a3, ra, 257f
                  bltu        s7, t1, 249f
244:              slt         s5, s6, s0
                  xor         s3, s11, t4
                  slt         s7, s7, t1
                  div         s2, a3, a3
                  lui         s1, 970131
249:              and         zero, t5, s1
                  subw        t2, s8, a4
                  divuw       gp, sp, a1
                  addw        s7, tp, t1
253:              div         s5, s1, t6
                  addw        s5, s8, s5
255:              subw        zero, tp, a2
                  ori         t1, a6, 1105
257:              mulhu       s5, sp, a5
                  la x31, test_done
                  jalr x0, x31, 0
test_done:        
                  li gp, 1
                  j write_tohost
write_tohost:     
                  sw gp, tohost, t5
_exit:            
                  j write_tohost
.section .data
.align 6; .global tohost; tohost: .dword 0;
.align 6; .global fromhost; fromhost: .dword 0;
.section .user_stack,"aw",@progbits;
.align 2
user_stack_start:
.rept 4999
.8byte 0x0
.endr
user_stack_end:
.8byte 0x0

"#
);
// Declare the asm function as extern "C"
extern "C" {
    fn run_asm_test() -> u32; // Returns gp (1 for pass)
}

sp1_zkvm::entrypoint!(main);
pub fn main() {
    // Read an input to the program.
    //
    // Behind the scenes, this compiles down to a system call which handles reading inputs
    // from the prover.
    let n = sp1_zkvm::io::read::<u32>();

    // Write n to public input
    sp1_zkvm::io::commit(&n);

    // Compute the n'th fibonacci number, using normal Rust code.
    let mut a = 0;
    let mut b = 1;
    for _ in 0..n {
        let mut c = a + b;
        c %= 7919; // Modulus to prevent overflow.
        a = b;
        b = c;
    }

    // Initialize registers with known values
    // let mut reg_t0: u32 = 0;
    // let mut reg_t1: u32 = 42;
    // let mut reg_t2: u32 = 100;
    // let mut reg_t3: u32 = 200;

    // Stack pointer initialization
    // let stack_ptr: u32 = 0x1000;

    // Commit initial state
    // sp1_zkvm::io::commit(&reg_t0);
    // sp1_zkvm::io::commit(&reg_t1);
    // sp1_zkvm::io::commit(&reg_t2);

    let result = unsafe { run_asm_test() };

    // Commit public output (replaces tohost write)
    // commit(&result);

    // Execute generated assembly instructions
    // unsafe {
    //     asm!(
    //         "
    //         slli        t6, t3, 20
    //               lui         t6, 4419
    //               xor         a6, a2, s9
    //               sub         s8, s8, t0
    //               sltiu       gp, sp, -1707
    //               or          s5, a2, t5
    //               sra         a7, t1, s6
    //               slli        s2, s7, 14
    //               srli        a0, s4, 28
    //               sltiu       t5, t5, 1558
    //               sltiu       zero, s1, 878
    //               and         s5, s2, s0
    //               srai        t0, a2, 30
    //               slli        t5, a4, 14
    //               slli        s10, a7, 20
    //               srai        s7, s7, 11
    //               add         t6, s8, s7
    //               sll         a3, t5, s11
    //               slli        a5, s11, 31
    //               srai        t5, gp, 22
    //               auipc       s10, 353950
    //               xori        gp, t0, 689
    //               add         t4, t4, s9
    //               srli        a7, zero, 2
    //               xori        t1, sp, -391
    //               srl         a3, a1, a7
    //               addi        s6, t1, -342
    //               slti        s2, s3, 2014
    //               ori         t3, a0, 1674
    //               xor         zero, t4, a7
    //               sltu        s7, a5, s8
    //               andi        a3, s3, -168
    //               and         a6, a3, s2
    //               sltu        t1, s5, s3
    //               sra         zero, tp, s9
    //               and         a7, s4, t4
    //               andi        ra, a3, -581
    //               slli        t1, s1, 21
    //               slti        s3, ra, -496
    //               andi        ra, t2, 978
    //               sub         a5, s9, s2
    //               nop
    //               srai        s7, s2, 27
    //               xor         t3, s10, a6
    //               xori        zero, s7, 1668
    //               xori        s3, s7, -2010
    //               sltiu       s3, s4, -1282
    //               xor         gp, s1, a1
    //               sltiu       zero, a7, -259
    //               srai        s2, ra, 4
    //               lui         s4, 696115
    //               add         a6, t6, a3
    //               sll         s1, a6, a4
    //               sll         a5, s6, t0
    //               slti        t6, t4, 1095
    //               ori         t6, a1, 588
    //               sra         zero, s0, t4
    //               slt         t6, a3, t0
    //               xori        s1, s8, 1622
    //               andi        s1, ra, 2
    //               add         t5, t4, t5
    //               srl         t5, t5, t2
    //               and         t3, zero, t3
    //               srli        s8, tp, 12
    //               andi        s3, zero, 478
    //               auipc       s2, 793670
    //               sub         zero, t5, s3
    //               andi        s1, s3, -857
    //               sll         t2, tp, tp
    //               addi        zero, s11, 936
    //               sll         s6, a1, a2
    //               slli        t5, s2, 3
    //               sub         a2, a7, t5
    //               sub         zero, a4, a6
    //               and         sp, t1, a6
    //               srl         tp, s1, a7
    //               xori        s2, t5, 501
    //               slt         s9, a1, s4
    //               slti        s1, s8, 593
    //               andi        s6, a2, -559
    //               auipc       a2, 229814
    //               and         t4, s5, a0
    //               sltu        zero, s11, t3
    //               sra         s2, s2, t6
    //               and         s4, a3, t2
    //               xori        s7, s5, -730
    //               sltiu       a0, a7, 1052
    //               add         zero, s10, t2
    //               sub         s5, s10, t4
    //               xori        t4, t6, 204
    //               srli        a6, s8, 18
    //               sll         s1, s0, sp
    //               xori        t2, s8, 45
    //               andi        a1, t0, 150
    //               nop
    //               sltu        a0, t1, s8
    //               add         gp, a7, ra
    //               slli        zero, t4, 3
    //               sll         a2, s9, t0
    //               slt         s7, t4, t4
    //               or          a7, a0, a2
    //               srli        a3, ra, 0
    //               xor         a3, zero, s4
    //               and         zero, t0, a1
    //               add         sp, s2, t1
    //               srai        t3, s6, 4
    //               sll         a3, a4, zero
    //               srai        zero, t5, 30
    //               add         zero, a0, a7
    //               slt         s9, a2, s2
    //               sll         a3, t1, t3
    //               lui         t3, 97642
    //               ori         gp, a1, -940
    //               srl         s7, gp, s9
    //               addi        a5, a7, -1024
    //               lui         t6, 485132
    //               addi        t1, a4, -1149
    //               auipc       s2, 657858
    //               add         t0, zero, s3
    //               slti        s4, a7, -991
    //               sltiu       s7, ra, -2008
    //               add         t3, a0, a0
    //               ori         s3, a3, -1699
    //               nop
    //               xor         t0, zero, t1
    //               xori        t1, a2, 1938
    //               sltiu       s3, tp, 1504
    //               sub         gp, s0, tp
    //               sltiu       s7, tp, -1167
    //               or          s4, a5, t6
    //               srl         zero, s0, t2
    //               sra         zero, a4, t0
    //               add         s9, s7, s1
    //               srli        t1, s11, 21
    //               slli        s9, a6, 30
    //               xor         ra, s6, a6
    //               slt         s5, t4, s7
    //               nop
    //               xori        s1, t2, -833
    //               andi        t6, s10, 1558
    //               sll         a7, sp, t1
    //               ori         s5, a1, -360
    //               or          s1, s9, s4
    //               nop
    //               sltiu       t6, a4, -787
    //               slti        sp, a5, 671
    //               addi        s2, s6, -587
    //               srl         s6, s1, s5
    //               lui         t6, 171398
    //               sll         t5, a7, s0
    //               xori        ra, t4, 836
    //               auipc       a0, 1018810
    //               and         t6, t5, t3
    //               sra         s8, a6, s10
    //               sll         s5, s10, zero
    //               auipc       t4, 713505
    //               sltiu       a6, s11, 1925
    //               xor         t5, zero, t5
    //               sltiu       s7, s10, 994
    //               sra         a2, s4, sp
    //               srl         s4, s3, a7
    //               andi        s6, ra, 1801
    //               addi        s7, s3, 514
    //               ori         a6, t3, 1497
    //               xori        zero, a0, -1529
    //               auipc       s5, 22520
    //               srl         s4, a7, s6
    //               addi        t4, a4, 340
    //               auipc       s6, 255653
    //               sll         a0, ra, s10
    //               and         zero, t5, s5
    //               sra         gp, t5, a4
    //               slli        s9, a2, 20
    //               nop
    //               slti        t6, a1, 856
    //               xori        a5, s5, 1350
    //               slt         s3, s8, a1
    //               xor         t4, t1, t3
    //               sltu        s3, gp, a4
    //               or          a2, s6, t0
    //               srl         s5, s11, s11
    //               slt         t1, s7, a5
    //               srl         s4, t5, s7
    //               srli        a5, s11, 15
    //               srli        tp, s2, 13
    //               slti        t4, t3, 2019
    //               sltu        s2, s0, s11
    //               slt         zero, s8, a5
    //               sltiu       gp, ra, 1717
    //               lui         sp, 369432
    //               srl         a3, sp, a0
    //               sub         a6, s8, t1
    //               andi        t0, tp, -1944
    //               xori        a6, t0, -1495
    //               auipc       sp, 124470
    //               sra         s5, t4, tp
    //               sltiu       s3, s2, -1132
    //               sra         a2, t5, a7
    //               xori        t5, ra, -780
    //               srl         ra, ra, a5
    //               andi        a6, s4, 1326
    //               srai        a2, t2, 11
    //               sra         t0, s3, t3
    //               sltiu       t6, a6, -1981
    //               slli        t0, a6, 21
    //               srli        zero, s2, 26
    //               srli        s1, s10, 7
    //               sra         s8, s1, a5
    //               xori        a7, t4, 1075
    //               and         t3, a2, a4
    //               auipc       a1, 472083
    //               slli        a0, sp, 26
    //               andi        a5, a4, -2008
    //               andi        sp, s4, 1239
    //               ori         sp, zero, 1775
    //     "
    //     );
    // }

    // Commit final state
    // sp1_zkvm::io::commit(&reg_t0);
    // sp1_zkvm::io::commit(&result);
    // sp1_zkvm::io::commit(&reg_t2);

    // Write the output of the program.
    //
    // Behind the scenes, this also compiles down to a system call which handles writing
    // outputs to the prover.
    sp1_zkvm::io::commit(&a);
    sp1_zkvm::io::commit(&b);
}
