use regalloc::{Reg, RegClass};
use std::backtrace::Backtrace;

use crate::isa::x64::inst::*;

fn low8willSXto64(x: u32) -> bool {
    let xs = (x as i32) as i64;
    xs == ((xs << 56) >> 56)
}

fn low8willSXto32(x: u32) -> bool {
    let xs = x as i32;
    xs == ((xs << 24) >> 24)
}

//=============================================================================
// Instructions and subcomponents: emission

// For all of the routines that take both a memory-or-reg operand (sometimes
// called "E" in the Intel documentation) and a reg-only operand ("G" in
// Intelese), the order is always G first, then E.
//
// "enc" in the following means "hardware register encoding number".

#[inline(always)]
fn mkModRegRM(m0d: u8, encRegG: u8, rmE: u8) -> u8 {
    debug_assert!(m0d < 4);
    debug_assert!(encRegG < 8);
    debug_assert!(rmE < 8);
    ((m0d & 3) << 6) | ((encRegG & 7) << 3) | (rmE & 7)
}

#[inline(always)]
fn mkSIB(shift: u8, encIndex: u8, encBase: u8) -> u8 {
    debug_assert!(shift < 4);
    debug_assert!(encIndex < 8);
    debug_assert!(encBase < 8);
    ((shift & 3) << 6) | ((encIndex & 7) << 3) | (encBase & 7)
}

#[inline(always)]
// Get the encoding number from something which we sincerely hope is a real
// register of class I64.
fn iregEnc(reg: Reg) -> u8 {
    debug_assert!(reg.is_real());
    debug_assert!(reg.get_class() == RegClass::I64);
    reg.get_hw_encoding()
}

// F_*: these flags describe special handling of the insn to be generated.  Be
// careful with these.  It is easy to create nonsensical combinations.
const F_NONE: u32 = 0;

// Emit the REX prefix byte even if it appears to be redundant (== 0x40).
const F_RETAIN_REDUNDANT_REX: u32 = 1;

// Set the W bit in the REX prefix to zero.  By default it will be set to 1,
// indicating a 64-bit operation.
const F_CLEAR_REX_W: u32 = 2;

// Add an 0x66 (operand-size override) prefix.  This is necessary to indicate
// a 16-bit operation.  Normally this will be used together with F_CLEAR_REX_W.
const F_PREFIX_66: u32 = 4;

// This is the core 'emit' function for instructions that reference memory.
//
// For an instruction that has as operands a register |encG| and a memory
// address |memE|, create and emit, first the REX prefix, then caller-supplied
// opcode byte(s) (|opcodes| and |numOpcodes|), then the MOD/RM byte, then
// optionally, a SIB byte, and finally optionally an immediate that will be
// derived from the |memE| operand.  For most instructions up to and including
// SSE4.2, that will be the whole instruction.
//
// The opcodes are written bigendianly for the convenience of callers.  For
// example, if the opcode bytes to be emitted are, in this order, F3 0F 27,
// then the caller should pass |opcodes| == 0xF3_0F_27 and |numOpcodes| == 3.
//
// The register operand is represented here not as a |Reg| but as its hardware
// encoding, |encG|.  |flags| can specify special handling for the REX prefix.
// By default, the REX prefix will indicate a 64-bit operation and will be
// deleted if it is redundant (0x40).  Note that for a 64-bit operation, the
// REX prefix will normally never be redundant, since REX.W must be 1 to
// indicate a 64-bit operation.
fn emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE<O: MachSectionOutput>(
    sink: &mut O,
    opcodes: u32,
    mut numOpcodes: usize,
    encG: u8,
    memE: &Addr,
    flags: u32,
) {
    println!("EMIT REX OPCODES 1\n");
    // General comment for this function: the registers in |memE| must be
    // 64-bit integer registers, because they are part of an address
    // expression.  But |encG| can be derived from a register of any class.
    let prefix66 = (flags & F_PREFIX_66) != 0;
    let clearRexW = (flags & F_CLEAR_REX_W) != 0;
    let retainRedundant = (flags & F_RETAIN_REDUNDANT_REX) != 0;
    // The operand-size override, if requested.  This indicates a 16-bit
    // operation.
    if prefix66 {
        sink.put1(0x66);
    }
    match memE {
        Addr::IR { simm32, base: regE } => {
            // First, cook up the REX byte.  This is easy.
            let encE = iregEnc(*regE);
            let w = if clearRexW { 0 } else { 1 };
            let r = (encG >> 3) & 1;
            let x = 0;
            let b = (encE >> 3) & 1;
            let rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
            if rex != 0x40 || retainRedundant {
                sink.put1(rex);
            }
            // Now the opcode(s).  These include any other prefixes the caller
            // hands to us.
            while numOpcodes > 0 {
                numOpcodes -= 1;
                sink.put1(((opcodes >> (numOpcodes << 3)) & 0xFF) as u8);
            }
            // Now the mod/rm and associated immediates.  This is
            // significantly complicated due to the multiple special cases.
            if *simm32 == 0
                && encE != regs::ENC_RSP
                && encE != regs::ENC_RBP
                && encE != regs::ENC_R12
                && encE != regs::ENC_R13
            {
                // FIXME JRS 2020Feb11: those four tests can surely be
                // replaced by a single mask-and-compare check.  We should do
                // that because this routine is likely to be hot.
                sink.put1(mkModRegRM(0, encG & 7, encE & 7));
            } else if *simm32 == 0 && (encE == regs::ENC_RSP || encE == regs::ENC_R12) {
                sink.put1(mkModRegRM(0, encG & 7, 4));
                sink.put1(0x24);
            } else if low8willSXto32(*simm32) && encE != regs::ENC_RSP && encE != regs::ENC_R12 {
                sink.put1(mkModRegRM(1, encG & 7, encE & 7));
                sink.put1((simm32 & 0xFF) as u8);
            } else if encE != regs::ENC_RSP && encE != regs::ENC_R12 {
                sink.put1(mkModRegRM(2, encG & 7, encE & 7));
                sink.put4(*simm32);
            } else if (encE == regs::ENC_RSP || encE == regs::ENC_R12) && low8willSXto32(*simm32) {
                // REX.B distinguishes RSP from R12
                sink.put1(mkModRegRM(1, encG & 7, 4));
                sink.put1(0x24);
                sink.put1((simm32 & 0xFF) as u8);
            } else if encE == regs::ENC_R12 || encE == regs::ENC_RSP {
                //.. wait for test case for RSP case
                // REX.B distinguishes RSP from R12
                sink.put1(mkModRegRM(2, encG & 7, 4));
                sink.put1(0x24);
                sink.put4(*simm32);
            } else {
                panic!("emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE: IR");
            }
        }
        // Bizarrely, the IRRS case is much simpler.
        Addr::IRRS {
            simm32,
            base: regBase,
            index: regIndex,
            shift,
        } => {
            let encBase = iregEnc(*regBase);
            let encIndex = iregEnc(*regIndex);
            // The rex byte
            let w = if clearRexW { 0 } else { 1 };
            let r = (encG >> 3) & 1;
            let x = (encIndex >> 3) & 1;
            let b = (encBase >> 3) & 1;
            let rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
            if rex != 0x40 || retainRedundant {
                sink.put1(rex);
            }
            // All other prefixes and opcodes
            while numOpcodes > 0 {
                numOpcodes -= 1;
                sink.put1(((opcodes >> (numOpcodes << 3)) & 0xFF) as u8);
            }
            // modrm, SIB, immediates
            if low8willSXto32(*simm32) && encIndex != regs::ENC_RSP {
                sink.put1(mkModRegRM(1, encG & 7, 4));
                sink.put1(mkSIB(*shift, encIndex & 7, encBase & 7));
                sink.put1(*simm32 as u8);
            } else if encIndex != regs::ENC_RSP {
                sink.put1(mkModRegRM(2, encG & 7, 4));
                sink.put1(mkSIB(*shift, encIndex & 7, encBase & 7));
                sink.put4(*simm32);
            } else {
                panic!("emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE: IRRS");
            }
        }
    }
}

// This is the core 'emit' function for instructions that do not reference
// memory.
//
// This is conceptually the same as
// emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE, except it is for the case
// where the E operand is a register rather than memory.  Hence it is much
// simpler.
fn emit_REX_OPCODES_MODRM_encG_encE<O: MachSectionOutput>(
    sink: &mut O,
    opcodes: u32,
    mut numOpcodes: usize,
    encG: u8,
    encE: u8,
    flags: u32,
) {
    println!("EMIT REX OPCODES 2\n");
    // EncG and EncE can be derived from registers of any class, and they
    // don't even have to be from the same class.  For example, for an
    // integer-to-FP conversion insn, one might be RegClass::I64 and the other
    // RegClass::V128.
    let prefix66 = (flags & F_PREFIX_66) != 0;
    let clearRexW = (flags & F_CLEAR_REX_W) != 0;
    let retainRedundant = (flags & F_RETAIN_REDUNDANT_REX) != 0;
    // The operand-size override
    if prefix66 {
        sink.put1(0x66);
    }
    // The rex byte
    let w = if clearRexW { 0 } else { 1 };
    let r = (encG >> 3) & 1;
    let x = 0;
    let b = (encE >> 3) & 1;
    let rex = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
    if rex != 0x40 || retainRedundant {
        sink.put1(rex);
    }
    // All other prefixes and opcodes
    while numOpcodes > 0 {
        numOpcodes -= 1;
        sink.put1(((opcodes >> (numOpcodes << 3)) & 0xFF) as u8);
    }
    // Now the mod/rm byte.  The instruction we're generating doesn't access
    // memory, so there is no SIB byte or immediate -- we're done.
    sink.put1(mkModRegRM(3, encG & 7, encE & 7));
}

// These are merely wrappers for the above two functions that facilitate passing
// actual |Reg|s rather than their encodings.
fn emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE<O: MachSectionOutput>(
    sink: &mut O,
    opcodes: u32,
    numOpcodes: usize,
    regG: Reg,
    memE: &Addr,
    flags: u32,
) {
    println!("EMIT REX OPCODES 3\n");
    // JRS FIXME 2020Feb07: this should really just be |regEnc| not |iregEnc|
    let encG = iregEnc(regG);
    emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE(sink, opcodes, numOpcodes, encG, memE, flags);
}

fn emit_REX_OPCODES_MODRM_regG_regE<O: MachSectionOutput>(
    sink: &mut O,
    opcodes: u32,
    numOpcodes: usize,
    regG: Reg,
    regE: Reg,
    flags: u32,
) {
    //let bt = Backtrace::force_capture();
    println!("EMIT REX OPCODES 4\n");
    // JRS FIXME 2020Feb07: these should really just be |regEnc| not |iregEnc|
    let encG = iregEnc(regG);
    let encE = iregEnc(regE);
    emit_REX_OPCODES_MODRM_encG_encE(sink, opcodes, numOpcodes, encG, encE, flags);
}

// Write a suitable number of bits from an imm64 to the sink.
fn emit_simm<O: MachSectionOutput>(sink: &mut O, size: u8, simm32: u32) {
    match size {
        8 | 4 => sink.put4(simm32),
        2 => sink.put2(simm32 as u16),
        1 => sink.put1(simm32 as u8),
        _ => panic!("x64::Inst::emit_simm: unreachable"),
    }
}
// The top-level emit function.
//
// Important!  Do not add improved (shortened) encoding cases to existing
// instructions without also adding tests for those improved encodings.  That
// is a dangerous game that leads to hard-to-track-down errors in the emitted
// code.
//
// For all instructions, make sure to have test coverage for all of the
// following situations.  Do this by creating the cross product resulting from
// applying the following rules to each operand:
//
// (1) for any insn that mentions a register: one test using a register from
//     the group [rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi] and a second one
//     using a register from the group [r8, r9, r10, r11, r12, r13, r14, r15].
//     This helps detect incorrect REX prefix construction.
//
// (2) for any insn that mentions a byte register: one test for each of the
//     four encoding groups [al, cl, dl, bl], [spl, bpl, sil, dil],
//     [r8b .. r11b] and [r12b .. r15b].  This checks that
//     apparently-redundant REX prefixes are retained when required.
//
// (3) for any insn that contains an immediate field, check the following
//     cases: field is zero, field is in simm8 range (-128 .. 127), field is
//     in simm32 range (-0x8000_0000 .. 0x7FFF_FFFF).  This is because some
//     instructions that require a 32-bit immediate have a short-form encoding
//     when the imm is in simm8 range.
//
// Rules (1), (2) and (3) don't apply for registers within address expressions
// (|Addr|s).  Those are already pretty well tested, and the registers in them
// don't have any effect on the containing instruction (apart from possibly
// require REX prefix bits).
//
// When choosing registers for a test, avoid using registers with the same
// offset within a given group.  For example, don't use rax and r8, since they
// both have the lowest 3 bits as 000, and so the test won't detect errors
// where those 3-bit register sub-fields are confused by the emitter.  Instead
// use (eg) rax (lo3 = 000) and r9 (lo3 = 001).  Similarly, don't use (eg) cl
// and bpl since they have the same offset in their group; use instead (eg) cl
// and sil.
//
// For all instructions, also add a test that uses only low-half registers
// (rax .. rdi, xmm0 .. xmm7) etc, so as to check that any redundant REX
// prefixes are correctly omitted.  This low-half restriction must apply to
// _all_ registers in the insn, even those in address expressions.
//
// Following these rules creates large numbers of test cases, but it's the
// only way to make the emitter reliable.
//
// Known possible improvements:
//
// * there's a shorter encoding for shl/shr/sar by a 1-bit immediate.  (Do we
//   care?)

pub(crate) fn emit<O: MachSectionOutput>(inst: &Inst, sink: &mut O) {
    match inst {
        Inst::Nop { len: 0 } => {}
        Inst::Alu_RMI_R {
            is_64,
            op,
            src: srcE,
            dst: regG,
        } => {
            let flags = if *is_64 { F_NONE } else { F_CLEAR_REX_W };
            if *op == RMI_R_Op::Mul {
                // We kinda freeloaded Mul into RMI_R_Op, but it doesn't fit
                // the usual pattern, so we have to special-case it.
                match srcE {
                    RMI::R { reg: regE } => {
                        emit_REX_OPCODES_MODRM_regG_regE(sink, 0x0FAF, 2, *regG, *regE, flags);
                    }
                    RMI::M { addr } => {
                        emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                            sink, 0x0FAF, 2, *regG, addr, flags,
                        );
                    }
                    RMI::I { simm32 } => {
                        let useImm8 = low8willSXto32(*simm32);
                        let opcode = if useImm8 { 0x6B } else { 0x69 };
                        // Yes, really, regG twice.
                        emit_REX_OPCODES_MODRM_regG_regE(sink, opcode, 1, *regG, *regG, flags);
                        emit_simm(sink, if useImm8 { 1 } else { 4 }, *simm32);
                    }
                }
            } else {
                let (opcode_R, opcode_M, subopcode_I) = match op {
                    RMI_R_Op::Add => (0x01, 0x03, 0),
                    RMI_R_Op::Sub => (0x29, 0x2B, 5),
                    RMI_R_Op::And => (0x21, 0x23, 4),
                    RMI_R_Op::Or => (0x09, 0x0B, 1),
                    RMI_R_Op::Xor => (0x31, 0x33, 6),
                    RMI_R_Op::Mul => panic!("unreachable"),
                };
                match srcE {
                    RMI::R { reg: regE } => {
                        // Note.  The arguments .. regE .. regG .. sequence
                        // here is the opposite of what is expected.  I'm not
                        // sure why this is.  But I am fairly sure that the
                        // arg order could be switched back to the expected
                        // .. regG .. regE .. if opcode_rr is also switched
                        // over to the "other" basic integer opcode (viz, the
                        // R/RM vs RM/R duality).  However, that would mean
                        // that the test results won't be in accordance with
                        // the GNU as reference output.  In other words, the
                        // inversion exists as a result of using GNU as as a
                        // gold standard.
                        emit_REX_OPCODES_MODRM_regG_regE(sink, opcode_R, 1, *regE, *regG, flags);
                        // NB: if this is ever extended to handle byte size
                        // ops, be sure to retain redundant REX prefixes.
                    }
                    RMI::M { addr } => {
                        // Whereas here we revert to the "normal" G-E ordering.
                        emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                            sink, opcode_M, 1, *regG, addr, flags,
                        );
                    }
                    RMI::I { simm32 } => {
                        let useImm8 = low8willSXto32(*simm32);
                        let opcode = if useImm8 { 0x83 } else { 0x81 };
                        // And also here we use the "normal" G-E ordering.
                        let encG = iregEnc(*regG);
                        emit_REX_OPCODES_MODRM_encG_encE(sink, opcode, 1, subopcode_I, encG, flags);
                        emit_simm(sink, if useImm8 { 1 } else { 4 }, *simm32);
                    }
                }
            }
        }
        Inst::Imm_R {
            dst_is_64,
            simm64,
            dst,
        } => {
            let encDst = iregEnc(*dst);
            if *dst_is_64 {
                // FIXME JRS 2020Feb10: also use the 32-bit case here when
                // possible
                sink.put1(0x48 | ((encDst >> 3) & 1));
                sink.put1(0xB8 | (encDst & 7));
                sink.put8(*simm64);
            } else {
                if ((encDst >> 3) & 1) == 1 {
                    sink.put1(0x41);
                }
                sink.put1(0xB8 | (encDst & 7));
                sink.put4(*simm64 as u32);
            }
        }
        Inst::Mov_R_R { is_64, src, dst } => {
            println!("Instruction Move R_R {:?} {:?} {:?}\n", is_64, src, dst);
            let flags = if *is_64 { F_NONE } else { F_CLEAR_REX_W };
            emit_REX_OPCODES_MODRM_regG_regE(sink, 0x89, 1, *src, *dst, flags);
        }
        Inst::MovZX_M_R { extMode, addr, dst } => {
            match extMode {
                ExtMode::BL => {
                    // MOVZBL is (REX.W==0) 0F B6 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x0FB6,
                        2,
                        *dst,
                        addr,
                        F_CLEAR_REX_W,
                    )
                }
                ExtMode::BQ => {
                    // MOVZBQ is (REX.W==1) 0F B6 /r
                    // I'm not sure why the Intel manual offers different
                    // encodings for MOVZBQ than for MOVZBL.  AIUI they should
                    // achieve the same, since MOVZBL is just going to zero out
                    // the upper half of the destination anyway.
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x0FB6, 2, *dst, addr, F_NONE)
                }
                ExtMode::WL => {
                    // MOVZWL is (REX.W==0) 0F B7 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x0FB7,
                        2,
                        *dst,
                        addr,
                        F_CLEAR_REX_W,
                    )
                }
                ExtMode::WQ => {
                    // MOVZWQ is (REX.W==1) 0F B7 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x0FB7, 2, *dst, addr, F_NONE)
                }
                ExtMode::LQ => {
                    // This is just a standard 32 bit load, and we rely on the
                    // default zero-extension rule to perform the extension.
                    // MOV r/m32, r32 is (REX.W==0) 8B /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x8B,
                        1,
                        *dst,
                        addr,
                        F_CLEAR_REX_W,
                    )
                }
            }
        }
        Inst::Mov64_M_R { addr, dst } => {
            emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x8B, 1, *dst, addr, F_NONE)
        }
        Inst::MovSX_M_R { extMode, addr, dst } => {
            match extMode {
                ExtMode::BL => {
                    // MOVSBL is (REX.W==0) 0F BE /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x0FBE,
                        2,
                        *dst,
                        addr,
                        F_CLEAR_REX_W,
                    )
                }
                ExtMode::BQ => {
                    // MOVSBQ is (REX.W==1) 0F BE /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x0FBE, 2, *dst, addr, F_NONE)
                }
                ExtMode::WL => {
                    // MOVSWL is (REX.W==0) 0F BF /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x0FBF,
                        2,
                        *dst,
                        addr,
                        F_CLEAR_REX_W,
                    )
                }
                ExtMode::WQ => {
                    // MOVSWQ is (REX.W==1) 0F BF /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x0FBF, 2, *dst, addr, F_NONE)
                }
                ExtMode::LQ => {
                    // MOVSLQ is (REX.W==1) 63 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x63, 1, *dst, addr, F_NONE)
                }
            }
        }
        Inst::Mov_R_M { size, src, addr } => {
            match size {
                1 => {
                    // This is one of the few places where the presence of a
                    // redundant REX prefix changes the meaning of the
                    // instruction.
                    let encSrc = iregEnc(*src);
                    let retainRedundantRex = if encSrc >= 4 && encSrc <= 7 {
                        F_RETAIN_REDUNDANT_REX
                    } else {
                        0
                    };
                    // MOV r8, r/m8 is (REX.W==0) 88 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x88,
                        1,
                        *src,
                        addr,
                        F_CLEAR_REX_W | retainRedundantRex,
                    )
                }
                2 => {
                    // MOV r16, r/m16 is 66 (REX.W==0) 89 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x89,
                        1,
                        *src,
                        addr,
                        F_CLEAR_REX_W | F_PREFIX_66,
                    )
                }
                4 => {
                    // MOV r32, r/m32 is (REX.W==0) 89 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(
                        sink,
                        0x89,
                        1,
                        *src,
                        addr,
                        F_CLEAR_REX_W,
                    )
                }
                8 => {
                    // MOV r64, r/m64 is (REX.W==1) 89 /r
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, 0x89, 1, *src, addr, F_NONE)
                }
                _ => panic!("x64::Inst::Mov_R_M::emit: unreachable"),
            }
        }
        Inst::Shift_R {
            is_64,
            kind,
            nBits,
            dst,
        } => {
            let encDst = iregEnc(*dst);
            let subopcode = match kind {
                ShiftKind::Left => 4,
                ShiftKind::RightZ => 5,
                ShiftKind::RightS => 7,
            };
            if *nBits == 0 {
                // SHL/SHR/SAR %cl, reg32 is (REX.W==0) D3 /subopcode
                // SHL/SHR/SAR %cl, reg64 is (REX.W==1) D3 /subopcode
                emit_REX_OPCODES_MODRM_encG_encE(
                    sink,
                    0xD3,
                    1,
                    subopcode,
                    encDst,
                    if *is_64 { F_NONE } else { F_CLEAR_REX_W },
                );
            } else {
                // SHL/SHR/SAR $ib, reg32 is (REX.W==0) C1 /subopcode ib
                // SHL/SHR/SAR $ib, reg64 is (REX.W==1) C1 /subopcode ib
                // When the shift amount is 1, there's an even shorter
                // encoding, but we don't bother with that nicety here.
                emit_REX_OPCODES_MODRM_encG_encE(
                    sink,
                    0xC1,
                    1,
                    subopcode,
                    encDst,
                    if *is_64 { F_NONE } else { F_CLEAR_REX_W },
                );
                sink.put1(*nBits);
            }
        }
        Inst::Cmp_RMI_R {
            size,
            src: srcE,
            dst: regG,
        } => {
            let mut retainRedundantRex = 0;
            if *size == 1 {
                // Here, a redundant REX prefix changes the meaning of the
                // instruction.
                let encG = iregEnc(*regG);
                if encG >= 4 && encG <= 7 {
                    retainRedundantRex = F_RETAIN_REDUNDANT_REX;
                }
            }
            let mut flags = match size {
                8 => F_NONE,
                4 => F_CLEAR_REX_W,
                2 => F_CLEAR_REX_W | F_PREFIX_66,
                1 => F_CLEAR_REX_W | retainRedundantRex,
                _ => panic!("x64::Inst::Cmp_RMI_R::emit: unreachable"),
            };
            match srcE {
                RMI::R { reg: regE } => {
                    let opcode = if *size == 1 { 0x38 } else { 0x39 };
                    if *size == 1 {
                        // We also need to check whether the E register forces
                        // the use of a redundant REX.
                        let encE = iregEnc(*regE);
                        if encE >= 4 && encE <= 7 {
                            flags |= F_RETAIN_REDUNDANT_REX;
                        }
                    }
                    // Same comment re swapped args as for Alu_RMI_R.
                    emit_REX_OPCODES_MODRM_regG_regE(sink, opcode, 1, *regE, *regG, flags);
                }
                RMI::M { addr } => {
                    let opcode = if *size == 1 { 0x3A } else { 0x3B };
                    // Whereas here we revert to the "normal" G-E ordering.
                    emit_REX_OPCODES_MODRM_SIB_IMM_regG_memE(sink, opcode, 1, *regG, addr, flags);
                }
                RMI::I { simm32 } => {
                    // FIXME JRS 2020Feb11: there are shorter encodings for
                    // cmp $imm, rax/eax/ax/al.
                    let useImm8 = low8willSXto32(*simm32);
                    let opcode = if *size == 1 {
                        0x80
                    } else if useImm8 {
                        0x83
                    } else {
                        0x81
                    };
                    // And also here we use the "normal" G-E ordering.
                    let encG = iregEnc(*regG);
                    emit_REX_OPCODES_MODRM_encG_encE(
                        sink, opcode, 1, 7, /*subopcode*/
                        encG, flags,
                    );
                    emit_simm(sink, if useImm8 { 1 } else { *size }, *simm32);
                }
            }
        }
        Inst::Push64 { src } => {
            match src {
                RMI::R { reg } => {
                    let encReg = iregEnc(*reg);
                    let rex = 0x40 | ((encReg >> 3) & 1);
                    if rex != 0x40 {
                        sink.put1(rex);
                    }
                    sink.put1(0x50 | (encReg & 7));
                }
                RMI::M { addr } => {
                    emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE(
                        sink,
                        0xFF,
                        1,
                        6, /*subopcode*/
                        addr,
                        F_CLEAR_REX_W,
                    );
                }
                RMI::I { simm32 } => {
                    if low8willSXto64(*simm32) {
                        sink.put1(0x6A);
                        sink.put1(*simm32 as u8);
                    } else {
                        sink.put1(0x68);
                        sink.put4(*simm32);
                    }
                }
            }
        }
        Inst::Pop64 { dst } => {
            let encDst = iregEnc(*dst);
            if encDst >= 8 {
                // 0x41 == REX.{W=0, B=1}.  It seems that REX.W is irrelevant
                // here.
                sink.put1(0x41);
            }
            sink.put1(0x58 + (encDst & 7));
        }
        //
        // ** Inst::CallKnown
        //
        Inst::CallUnknown { dest } => {
            match dest {
                RM::R { reg } => {
                    let regEnc = iregEnc(*reg);
                    emit_REX_OPCODES_MODRM_encG_encE(
                        sink,
                        0xFF,
                        1,
                        2, /*subopcode*/
                        regEnc,
                        F_CLEAR_REX_W,
                    );
                }
                RM::M { addr } => {
                    emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE(
                        sink,
                        0xFF,
                        1,
                        2, /*subopcode*/
                        addr,
                        F_CLEAR_REX_W,
                    );
                }
            }
        }
        Inst::Ret {} => sink.put1(0xC3),

        Inst::JmpKnown {
            dest: BranchTarget::Block(..),
        } => {
            // Computation of block offsets/sizes.
            sink.put1(0);
            sink.put4(0);
        }
        Inst::JmpKnown {
            dest: BranchTarget::ResolvedOffset(_bix, offset),
        } if *offset >= -0x7FFF_FF00 && *offset <= 0x7FFF_FF00 => {
            // And now for real
            let mut offs_i32 = *offset as i32;
            offs_i32 -= 5;
            let offs_u32 = offs_i32 as u32;
            sink.put1(0xE9);
            sink.put4(offs_u32);
        }
        //
        // ** Inst::JmpCondSymm   XXXX should never happen
        //
        Inst::JmpCond {
            cc: _,
            target: BranchTarget::Block(..),
        } => {
            // This case occurs when we are computing block offsets / sizes,
            // prior to lowering block-index targets to concrete-offset targets.
            // Only the size matters, so let's emit 6 bytes, as below.
            sink.put1(0);
            sink.put1(0);
            sink.put4(0);
        }
        Inst::JmpCond {
            cc,
            target: BranchTarget::ResolvedOffset(_bix, offset),
        } if *offset >= -0x7FFF_FF00 && *offset <= 0x7FFF_FF00 => {
            // This insn is 6 bytes long.  Currently |offset| is relative to
            // the start of this insn, but the Intel encoding requires it to
            // be relative to the start of the next instruction.  Hence the
            // adjustment.
            let mut offs_i32 = *offset as i32;
            offs_i32 -= 6;
            let offs_u32 = offs_i32 as u32;
            sink.put1(0x0F);
            sink.put1(0x80 + cc.get_enc());
            sink.put4(offs_u32);
        }
        //
        // ** Inst::JmpCondCompound   XXXX should never happen
        //
        Inst::JmpUnknown { target } => {
            match target {
                RM::R { reg } => {
                    let regEnc = iregEnc(*reg);
                    emit_REX_OPCODES_MODRM_encG_encE(
                        sink,
                        0xFF,
                        1,
                        4, /*subopcode*/
                        regEnc,
                        F_CLEAR_REX_W,
                    );
                }
                RM::M { addr } => {
                    emit_REX_OPCODES_MODRM_SIB_IMM_encG_memE(
                        sink,
                        0xFF,
                        1,
                        4, /*subopcode*/
                        addr,
                        F_CLEAR_REX_W,
                    );
                }
            }
        }
        Inst::SSE_Scalar_Mov_R_R { is_64, src, dst } => {
            println!("TODO: emit Inst::SSE_Scalar_Mov_R_R");
        }
        Inst::SSE_Scalar_Alu_RM_R {
            is_64,
            op,
            src,
            dst,
        } => {
            println!("TODO: emit Inst::SSE_Scalar_Alu_RM_R");
        }
        _ => panic!("x64_emit: unhandled: {} ", inst.show_rru(None)),
    }
}

//=============================================================================
// Tests for the emitter

// See comments at the top of |fn x64_emit| for advice on how to create
// reliable test cases.

// to see stdout: cargo test -- --nocapture
//
// for this specific case:
//
// (cd cranelift-codegen && \
// RUST_BACKTRACE=1 \
//       cargo test isa::x64::inst::test_x64_insn_encoding_and_printing \
//                  -- --nocapture)

#[cfg(test)]
use crate::isa::test_utils;

#[test]
fn test_x64_insn_encoding_and_printing() {
    let rax = info_RAX().0.to_reg();
    let rbx = info_RBX().0.to_reg();
    let rcx = info_RCX().0.to_reg();
    let rdx = info_RDX().0.to_reg();
    let rsi = info_RSI().0.to_reg();
    let rdi = info_RDI().0.to_reg();
    let rsp = info_RSP().0.to_reg();
    let rbp = info_RBP().0.to_reg();
    let r8 = info_R8().0.to_reg();
    let r9 = info_R9().0.to_reg();
    let r10 = info_R10().0.to_reg();
    let r11 = info_R11().0.to_reg();
    let r12 = info_R12().0.to_reg();
    let r13 = info_R13().0.to_reg();
    let r14 = info_R14().0.to_reg();
    let r15 = info_R15().0.to_reg();

    // And Writable<> versions of the same:
    let w_rax = Writable::<Reg>::from_reg(info_RAX().0.to_reg());
    let w_rbx = Writable::<Reg>::from_reg(info_RBX().0.to_reg());
    let w_rcx = Writable::<Reg>::from_reg(info_RCX().0.to_reg());
    let w_rdx = Writable::<Reg>::from_reg(info_RDX().0.to_reg());
    let w_rsi = Writable::<Reg>::from_reg(info_RSI().0.to_reg());
    let w_rdi = Writable::<Reg>::from_reg(info_RDI().0.to_reg());
    let _w_rsp = Writable::<Reg>::from_reg(info_RSP().0.to_reg());
    let _w_rbp = Writable::<Reg>::from_reg(info_RBP().0.to_reg());
    let w_r8 = Writable::<Reg>::from_reg(info_R8().0.to_reg());
    let w_r9 = Writable::<Reg>::from_reg(info_R9().0.to_reg());
    let _w_r10 = Writable::<Reg>::from_reg(info_R10().0.to_reg());
    let w_r11 = Writable::<Reg>::from_reg(info_R11().0.to_reg());
    let w_r12 = Writable::<Reg>::from_reg(info_R12().0.to_reg());
    let w_r13 = Writable::<Reg>::from_reg(info_R13().0.to_reg());
    let w_r14 = Writable::<Reg>::from_reg(info_R14().0.to_reg());
    let w_r15 = Writable::<Reg>::from_reg(info_R15().0.to_reg());

    let mut insns = Vec::<(Inst, &str, &str)>::new();

    // ========================================================
    // Cases aimed at checking Addr-esses: IR (Imm + Reg)
    //
    // These are just a bunch of loads with all supported (by the emitter)
    // permutations of address formats.
    //
    // Addr_IR, offset zero
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rax), w_rdi),
        "488B38",
        "movq    0(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rbx), w_rdi),
        "488B3B",
        "movq    0(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rcx), w_rdi),
        "488B39",
        "movq    0(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rdx), w_rdi),
        "488B3A",
        "movq    0(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rbp), w_rdi),
        "488B7D00",
        "movq    0(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rsp), w_rdi),
        "488B3C24",
        "movq    0(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rsi), w_rdi),
        "488B3E",
        "movq    0(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, rdi), w_rdi),
        "488B3F",
        "movq    0(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r8), w_rdi),
        "498B38",
        "movq    0(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r9), w_rdi),
        "498B39",
        "movq    0(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r10), w_rdi),
        "498B3A",
        "movq    0(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r11), w_rdi),
        "498B3B",
        "movq    0(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r12), w_rdi),
        "498B3C24",
        "movq    0(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r13), w_rdi),
        "498B7D00",
        "movq    0(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r14), w_rdi),
        "498B3E",
        "movq    0(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0, r15), w_rdi),
        "498B3F",
        "movq    0(%r15), %rdi",
    ));

    // ========================================================
    // Addr_IR, offset max simm8
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rax), w_rdi),
        "488B787F",
        "movq    127(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rbx), w_rdi),
        "488B7B7F",
        "movq    127(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rcx), w_rdi),
        "488B797F",
        "movq    127(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rdx), w_rdi),
        "488B7A7F",
        "movq    127(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rbp), w_rdi),
        "488B7D7F",
        "movq    127(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rsp), w_rdi),
        "488B7C247F",
        "movq    127(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rsi), w_rdi),
        "488B7E7F",
        "movq    127(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, rdi), w_rdi),
        "488B7F7F",
        "movq    127(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r8), w_rdi),
        "498B787F",
        "movq    127(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r9), w_rdi),
        "498B797F",
        "movq    127(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r10), w_rdi),
        "498B7A7F",
        "movq    127(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r11), w_rdi),
        "498B7B7F",
        "movq    127(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r12), w_rdi),
        "498B7C247F",
        "movq    127(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r13), w_rdi),
        "498B7D7F",
        "movq    127(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r14), w_rdi),
        "498B7E7F",
        "movq    127(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(127, r15), w_rdi),
        "498B7F7F",
        "movq    127(%r15), %rdi",
    ));

    // ========================================================
    // Addr_IR, offset min simm8
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rax), w_rdi),
        "488B7880",
        "movq    -128(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rbx), w_rdi),
        "488B7B80",
        "movq    -128(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rcx), w_rdi),
        "488B7980",
        "movq    -128(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rdx), w_rdi),
        "488B7A80",
        "movq    -128(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rbp), w_rdi),
        "488B7D80",
        "movq    -128(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rsp), w_rdi),
        "488B7C2480",
        "movq    -128(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rsi), w_rdi),
        "488B7E80",
        "movq    -128(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, rdi), w_rdi),
        "488B7F80",
        "movq    -128(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r8), w_rdi),
        "498B7880",
        "movq    -128(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r9), w_rdi),
        "498B7980",
        "movq    -128(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r10), w_rdi),
        "498B7A80",
        "movq    -128(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r11), w_rdi),
        "498B7B80",
        "movq    -128(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r12), w_rdi),
        "498B7C2480",
        "movq    -128(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r13), w_rdi),
        "498B7D80",
        "movq    -128(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r14), w_rdi),
        "498B7E80",
        "movq    -128(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-128i32 as u32, r15), w_rdi),
        "498B7F80",
        "movq    -128(%r15), %rdi",
    ));

    // ========================================================
    // Addr_IR, offset smallest positive simm32
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rax), w_rdi),
        "488BB880000000",
        "movq    128(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rbx), w_rdi),
        "488BBB80000000",
        "movq    128(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rcx), w_rdi),
        "488BB980000000",
        "movq    128(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rdx), w_rdi),
        "488BBA80000000",
        "movq    128(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rbp), w_rdi),
        "488BBD80000000",
        "movq    128(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rsp), w_rdi),
        "488BBC2480000000",
        "movq    128(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rsi), w_rdi),
        "488BBE80000000",
        "movq    128(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, rdi), w_rdi),
        "488BBF80000000",
        "movq    128(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r8), w_rdi),
        "498BB880000000",
        "movq    128(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r9), w_rdi),
        "498BB980000000",
        "movq    128(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r10), w_rdi),
        "498BBA80000000",
        "movq    128(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r11), w_rdi),
        "498BBB80000000",
        "movq    128(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r12), w_rdi),
        "498BBC2480000000",
        "movq    128(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r13), w_rdi),
        "498BBD80000000",
        "movq    128(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r14), w_rdi),
        "498BBE80000000",
        "movq    128(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(128, r15), w_rdi),
        "498BBF80000000",
        "movq    128(%r15), %rdi",
    ));

    // ========================================================
    // Addr_IR, offset smallest negative simm32
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rax), w_rdi),
        "488BB87FFFFFFF",
        "movq    -129(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rbx), w_rdi),
        "488BBB7FFFFFFF",
        "movq    -129(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rcx), w_rdi),
        "488BB97FFFFFFF",
        "movq    -129(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rdx), w_rdi),
        "488BBA7FFFFFFF",
        "movq    -129(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rbp), w_rdi),
        "488BBD7FFFFFFF",
        "movq    -129(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rsp), w_rdi),
        "488BBC247FFFFFFF",
        "movq    -129(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rsi), w_rdi),
        "488BBE7FFFFFFF",
        "movq    -129(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, rdi), w_rdi),
        "488BBF7FFFFFFF",
        "movq    -129(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r8), w_rdi),
        "498BB87FFFFFFF",
        "movq    -129(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r9), w_rdi),
        "498BB97FFFFFFF",
        "movq    -129(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r10), w_rdi),
        "498BBA7FFFFFFF",
        "movq    -129(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r11), w_rdi),
        "498BBB7FFFFFFF",
        "movq    -129(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r12), w_rdi),
        "498BBC247FFFFFFF",
        "movq    -129(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r13), w_rdi),
        "498BBD7FFFFFFF",
        "movq    -129(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r14), w_rdi),
        "498BBE7FFFFFFF",
        "movq    -129(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-129i32 as u32, r15), w_rdi),
        "498BBF7FFFFFFF",
        "movq    -129(%r15), %rdi",
    ));

    // ========================================================
    // Addr_IR, offset large positive simm32
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rax), w_rdi),
        "488BB877207317",
        "movq    393420919(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rbx), w_rdi),
        "488BBB77207317",
        "movq    393420919(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rcx), w_rdi),
        "488BB977207317",
        "movq    393420919(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rdx), w_rdi),
        "488BBA77207317",
        "movq    393420919(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rbp), w_rdi),
        "488BBD77207317",
        "movq    393420919(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rsp), w_rdi),
        "488BBC2477207317",
        "movq    393420919(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rsi), w_rdi),
        "488BBE77207317",
        "movq    393420919(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, rdi), w_rdi),
        "488BBF77207317",
        "movq    393420919(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r8), w_rdi),
        "498BB877207317",
        "movq    393420919(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r9), w_rdi),
        "498BB977207317",
        "movq    393420919(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r10), w_rdi),
        "498BBA77207317",
        "movq    393420919(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r11), w_rdi),
        "498BBB77207317",
        "movq    393420919(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r12), w_rdi),
        "498BBC2477207317",
        "movq    393420919(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r13), w_rdi),
        "498BBD77207317",
        "movq    393420919(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r14), w_rdi),
        "498BBE77207317",
        "movq    393420919(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(0x17732077, r15), w_rdi),
        "498BBF77207317",
        "movq    393420919(%r15), %rdi",
    ));

    // ========================================================
    // Addr_IR, offset large negative simm32
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rax), w_rdi),
        "488BB8D9A6BECE",
        "movq    -826366247(%rax), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rbx), w_rdi),
        "488BBBD9A6BECE",
        "movq    -826366247(%rbx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rcx), w_rdi),
        "488BB9D9A6BECE",
        "movq    -826366247(%rcx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rdx), w_rdi),
        "488BBAD9A6BECE",
        "movq    -826366247(%rdx), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rbp), w_rdi),
        "488BBDD9A6BECE",
        "movq    -826366247(%rbp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rsp), w_rdi),
        "488BBC24D9A6BECE",
        "movq    -826366247(%rsp), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rsi), w_rdi),
        "488BBED9A6BECE",
        "movq    -826366247(%rsi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, rdi), w_rdi),
        "488BBFD9A6BECE",
        "movq    -826366247(%rdi), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r8), w_rdi),
        "498BB8D9A6BECE",
        "movq    -826366247(%r8), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r9), w_rdi),
        "498BB9D9A6BECE",
        "movq    -826366247(%r9), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r10), w_rdi),
        "498BBAD9A6BECE",
        "movq    -826366247(%r10), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r11), w_rdi),
        "498BBBD9A6BECE",
        "movq    -826366247(%r11), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r12), w_rdi),
        "498BBC24D9A6BECE",
        "movq    -826366247(%r12), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r13), w_rdi),
        "498BBDD9A6BECE",
        "movq    -826366247(%r13), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r14), w_rdi),
        "498BBED9A6BECE",
        "movq    -826366247(%r14), %rdi",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg(-0x31415927i32 as u32, r15), w_rdi),
        "498BBFD9A6BECE",
        "movq    -826366247(%r15), %rdi",
    ));

    // ========================================================
    // Cases aimed at checking Addr-esses: IRRS (Imm + Reg + (Reg << Shift))
    // Note these don't check the case where the index reg is RSP, since we
    // don't encode any of those.
    //
    // Addr_IRRS, offset max simm8
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, rax, rax, 0), w_r11),
        "4C8B5C007F",
        "movq    127(%rax,%rax,1), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, rdi, rax, 1), w_r11),
        "4C8B5C477F",
        "movq    127(%rdi,%rax,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, r8, rax, 2), w_r11),
        "4D8B5C807F",
        "movq    127(%r8,%rax,4), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, r15, rax, 3), w_r11),
        "4D8B5CC77F",
        "movq    127(%r15,%rax,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, rax, rdi, 3), w_r11),
        "4C8B5CF87F",
        "movq    127(%rax,%rdi,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, rdi, rdi, 2), w_r11),
        "4C8B5CBF7F",
        "movq    127(%rdi,%rdi,4), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, r8, rdi, 1), w_r11),
        "4D8B5C787F",
        "movq    127(%r8,%rdi,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(127, r15, rdi, 0), w_r11),
        "4D8B5C3F7F",
        "movq    127(%r15,%rdi,1), %r11",
    ));

    // ========================================================
    // Addr_IRRS, offset min simm8
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, rax, r8, 2), w_r11),
        "4E8B5C8080",
        "movq    -128(%rax,%r8,4), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, rdi, r8, 3), w_r11),
        "4E8B5CC780",
        "movq    -128(%rdi,%r8,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, r8, r8, 0), w_r11),
        "4F8B5C0080",
        "movq    -128(%r8,%r8,1), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, r15, r8, 1), w_r11),
        "4F8B5C4780",
        "movq    -128(%r15,%r8,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, rax, r15, 1), w_r11),
        "4E8B5C7880",
        "movq    -128(%rax,%r15,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, rdi, r15, 0), w_r11),
        "4E8B5C3F80",
        "movq    -128(%rdi,%r15,1), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, r8, r15, 3), w_r11),
        "4F8B5CF880",
        "movq    -128(%r8,%r15,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(-128i32 as u32, r15, r15, 2), w_r11),
        "4F8B5CBF80",
        "movq    -128(%r15,%r15,4), %r11",
    ));

    // ========================================================
    // Addr_IRRS, offset large positive simm32
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, rax, rax, 0), w_r11),
        "4C8B9C00BE25664F",
        "movq    1332094398(%rax,%rax,1), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, rdi, rax, 1), w_r11),
        "4C8B9C47BE25664F",
        "movq    1332094398(%rdi,%rax,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, r8, rax, 2), w_r11),
        "4D8B9C80BE25664F",
        "movq    1332094398(%r8,%rax,4), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, r15, rax, 3), w_r11),
        "4D8B9CC7BE25664F",
        "movq    1332094398(%r15,%rax,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, rax, rdi, 3), w_r11),
        "4C8B9CF8BE25664F",
        "movq    1332094398(%rax,%rdi,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, rdi, rdi, 2), w_r11),
        "4C8B9CBFBE25664F",
        "movq    1332094398(%rdi,%rdi,4), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, r8, rdi, 1), w_r11),
        "4D8B9C78BE25664F",
        "movq    1332094398(%r8,%rdi,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(0x4f6625be, r15, rdi, 0), w_r11),
        "4D8B9C3FBE25664F",
        "movq    1332094398(%r15,%rdi,1), %r11",
    ));

    // ========================================================
    // Addr_IRRS, offset large negative simm32
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, rax, r8, 2),
            w_r11,
        ),
        "4E8B9C8070E9B2D9",
        "movq    -642586256(%rax,%r8,4), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, rdi, r8, 3),
            w_r11,
        ),
        "4E8B9CC770E9B2D9",
        "movq    -642586256(%rdi,%r8,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, r8, r8, 0),
            w_r11,
        ),
        "4F8B9C0070E9B2D9",
        "movq    -642586256(%r8,%r8,1), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, r15, r8, 1),
            w_r11,
        ),
        "4F8B9C4770E9B2D9",
        "movq    -642586256(%r15,%r8,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, rax, r15, 1),
            w_r11,
        ),
        "4E8B9C7870E9B2D9",
        "movq    -642586256(%rax,%r15,2), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, rdi, r15, 0),
            w_r11,
        ),
        "4E8B9C3F70E9B2D9",
        "movq    -642586256(%rdi,%r15,1), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, r8, r15, 3),
            w_r11,
        ),
        "4F8B9CF870E9B2D9",
        "movq    -642586256(%r8,%r15,8), %r11",
    ));
    insns.push((
        i_Mov64_M_R(
            Addr::imm_reg_reg_shift(-0x264d1690i32 as u32, r15, r15, 2),
            w_r11,
        ),
        "4F8B9CBF70E9B2D9",
        "movq    -642586256(%r15,%r15,4), %r11",
    ));

    // End of test cases for Addr
    // ========================================================

    // ========================================================
    // General tests for each insn.  Don't forget to follow the
    // guidelines commented just prior to |fn x64_emit|.
    //
    // Alu_RMI_R
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Add, RMI::reg(r15), w_rdx),
        "4C01FA",
        "addq    %r15, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::reg(rcx), w_r8),
        "4101C8",
        "addl    %ecx, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::reg(rcx), w_rsi),
        "01CE",
        "addl    %ecx, %esi",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Add, RMI::mem(Addr::imm_reg(99, rdi)), w_rdx),
        "48035763",
        "addq    99(%rdi), %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::mem(Addr::imm_reg(99, rdi)), w_r8),
        "44034763",
        "addl    99(%rdi), %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(
            false,
            RMI_R_Op::Add,
            RMI::mem(Addr::imm_reg(99, rdi)),
            w_rsi,
        ),
        "037763",
        "addl    99(%rdi), %esi",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Add, RMI::imm(-127i32 as u32), w_rdx),
        "4883C281",
        "addq    $-127, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Add, RMI::imm(-129i32 as u32), w_rdx),
        "4881C27FFFFFFF",
        "addq    $-129, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Add, RMI::imm(76543210), w_rdx),
        "4881C2EAF48F04",
        "addq    $76543210, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::imm(-127i32 as u32), w_r8),
        "4183C081",
        "addl    $-127, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::imm(-129i32 as u32), w_r8),
        "4181C07FFFFFFF",
        "addl    $-129, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::imm(-76543210i32 as u32), w_r8),
        "4181C0160B70FB",
        "addl    $-76543210, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::imm(-127i32 as u32), w_rsi),
        "83C681",
        "addl    $-127, %esi",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::imm(-129i32 as u32), w_rsi),
        "81C67FFFFFFF",
        "addl    $-129, %esi",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Add, RMI::imm(76543210), w_rsi),
        "81C6EAF48F04",
        "addl    $76543210, %esi",
    ));
    // This is pretty feeble
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Sub, RMI::reg(r15), w_rdx),
        "4C29FA",
        "subq    %r15, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::And, RMI::reg(r15), w_rdx),
        "4C21FA",
        "andq    %r15, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Or, RMI::reg(r15), w_rdx),
        "4C09FA",
        "orq     %r15, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Xor, RMI::reg(r15), w_rdx),
        "4C31FA",
        "xorq    %r15, %rdx",
    ));
    // Test all mul cases, though
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Mul, RMI::reg(r15), w_rdx),
        "490FAFD7",
        "imulq   %r15, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::reg(rcx), w_r8),
        "440FAFC1",
        "imull   %ecx, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::reg(rcx), w_rsi),
        "0FAFF1",
        "imull   %ecx, %esi",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Mul, RMI::mem(Addr::imm_reg(99, rdi)), w_rdx),
        "480FAF5763",
        "imulq   99(%rdi), %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::mem(Addr::imm_reg(99, rdi)), w_r8),
        "440FAF4763",
        "imull   99(%rdi), %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(
            false,
            RMI_R_Op::Mul,
            RMI::mem(Addr::imm_reg(99, rdi)),
            w_rsi,
        ),
        "0FAF7763",
        "imull   99(%rdi), %esi",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Mul, RMI::imm(-127i32 as u32), w_rdx),
        "486BD281",
        "imulq   $-127, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Mul, RMI::imm(-129i32 as u32), w_rdx),
        "4869D27FFFFFFF",
        "imulq   $-129, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(true, RMI_R_Op::Mul, RMI::imm(76543210), w_rdx),
        "4869D2EAF48F04",
        "imulq   $76543210, %rdx",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::imm(-127i32 as u32), w_r8),
        "456BC081",
        "imull   $-127, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::imm(-129i32 as u32), w_r8),
        "4569C07FFFFFFF",
        "imull   $-129, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::imm(-76543210i32 as u32), w_r8),
        "4569C0160B70FB",
        "imull   $-76543210, %r8d",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::imm(-127i32 as u32), w_rsi),
        "6BF681",
        "imull   $-127, %esi",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::imm(-129i32 as u32), w_rsi),
        "69F67FFFFFFF",
        "imull   $-129, %esi",
    ));
    insns.push((
        i_Alu_RMI_R(false, RMI_R_Op::Mul, RMI::imm(76543210), w_rsi),
        "69F6EAF48F04",
        "imull   $76543210, %esi",
    ));

    // ========================================================
    // Imm_R
    //
    insns.push((
        i_Imm_R(false, 1234567, w_r14),
        "41BE87D61200",
        "movl    $1234567, %r14d",
    ));
    insns.push((
        i_Imm_R(false, -126i64 as u64, w_r14),
        "41BE82FFFFFF",
        "movl    $-126, %r14d",
    ));
    insns.push((
        i_Imm_R(true, 1234567898765, w_r14),
        "49BE8D26FB711F010000",
        "movabsq $1234567898765, %r14",
    ));
    insns.push((
        i_Imm_R(true, -126i64 as u64, w_r14),
        "49BE82FFFFFFFFFFFFFF",
        "movabsq $-126, %r14",
    ));
    insns.push((
        i_Imm_R(false, 1234567, w_rcx),
        "B987D61200",
        "movl    $1234567, %ecx",
    ));
    insns.push((
        i_Imm_R(false, -126i64 as u64, w_rcx),
        "B982FFFFFF",
        "movl    $-126, %ecx",
    ));
    insns.push((
        i_Imm_R(true, 1234567898765, w_rsi),
        "48BE8D26FB711F010000",
        "movabsq $1234567898765, %rsi",
    ));
    insns.push((
        i_Imm_R(true, -126i64 as u64, w_rbx),
        "48BB82FFFFFFFFFFFFFF",
        "movabsq $-126, %rbx",
    ));

    // ========================================================
    // Mov_R_R
    insns.push((i_Mov_R_R(false, rbx, w_rsi), "89DE", "movl    %ebx, %esi"));
    insns.push((i_Mov_R_R(false, rbx, w_r9), "4189D9", "movl    %ebx, %r9d"));
    insns.push((
        i_Mov_R_R(false, r11, w_rsi),
        "4489DE",
        "movl    %r11d, %esi",
    ));
    insns.push((i_Mov_R_R(false, r12, w_r9), "4589E1", "movl    %r12d, %r9d"));
    insns.push((i_Mov_R_R(true, rbx, w_rsi), "4889DE", "movq    %rbx, %rsi"));
    insns.push((i_Mov_R_R(true, rbx, w_r9), "4989D9", "movq    %rbx, %r9"));
    insns.push((i_Mov_R_R(true, r11, w_rsi), "4C89DE", "movq    %r11, %rsi"));
    insns.push((i_Mov_R_R(true, r12, w_r9), "4D89E1", "movq    %r12, %r9"));

    // ========================================================
    // MovZX_M_R
    insns.push((
        i_MovZX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "0FB671F9",
        "movzbl  -7(%rcx), %esi",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "410FB658F9",
        "movzbl  -7(%r8), %ebx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "450FB64AF9",
        "movzbl  -7(%r10), %r9d",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "410FB653F9",
        "movzbl  -7(%r11), %edx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "480FB671F9",
        "movzbq  -7(%rcx), %rsi",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "490FB658F9",
        "movzbq  -7(%r8), %rbx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "4D0FB64AF9",
        "movzbq  -7(%r10), %r9",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "490FB653F9",
        "movzbq  -7(%r11), %rdx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "0FB771F9",
        "movzwl  -7(%rcx), %esi",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "410FB758F9",
        "movzwl  -7(%r8), %ebx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "450FB74AF9",
        "movzwl  -7(%r10), %r9d",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "410FB753F9",
        "movzwl  -7(%r11), %edx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "480FB771F9",
        "movzwq  -7(%rcx), %rsi",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "490FB758F9",
        "movzwq  -7(%r8), %rbx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "4D0FB74AF9",
        "movzwq  -7(%r10), %r9",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "490FB753F9",
        "movzwq  -7(%r11), %rdx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "8B71F9",
        "movl    -7(%rcx), %esi",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "418B58F9",
        "movl    -7(%r8), %ebx",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "458B4AF9",
        "movl    -7(%r10), %r9d",
    ));
    insns.push((
        i_MovZX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "418B53F9",
        "movl    -7(%r11), %edx",
    ));

    // ========================================================
    // Mov64_M_R
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, rax, rbx, 0), w_rcx),
        "488B8C18B3000000",
        "movq    179(%rax,%rbx,1), %rcx",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, rax, rbx, 0), w_r8),
        "4C8B8418B3000000",
        "movq    179(%rax,%rbx,1), %r8",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, rax, r9, 0), w_rcx),
        "4A8B8C08B3000000",
        "movq    179(%rax,%r9,1), %rcx",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, rax, r9, 0), w_r8),
        "4E8B8408B3000000",
        "movq    179(%rax,%r9,1), %r8",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, r10, rbx, 0), w_rcx),
        "498B8C1AB3000000",
        "movq    179(%r10,%rbx,1), %rcx",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, r10, rbx, 0), w_r8),
        "4D8B841AB3000000",
        "movq    179(%r10,%rbx,1), %r8",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, r10, r9, 0), w_rcx),
        "4B8B8C0AB3000000",
        "movq    179(%r10,%r9,1), %rcx",
    ));
    insns.push((
        i_Mov64_M_R(Addr::imm_reg_reg_shift(179, r10, r9, 0), w_r8),
        "4F8B840AB3000000",
        "movq    179(%r10,%r9,1), %r8",
    ));

    // ========================================================
    // MovSX_M_R
    insns.push((
        i_MovSX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "0FBE71F9",
        "movsbl  -7(%rcx), %esi",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "410FBE58F9",
        "movsbl  -7(%r8), %ebx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "450FBE4AF9",
        "movsbl  -7(%r10), %r9d",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BL, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "410FBE53F9",
        "movsbl  -7(%r11), %edx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "480FBE71F9",
        "movsbq  -7(%rcx), %rsi",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "490FBE58F9",
        "movsbq  -7(%r8), %rbx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "4D0FBE4AF9",
        "movsbq  -7(%r10), %r9",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::BQ, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "490FBE53F9",
        "movsbq  -7(%r11), %rdx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "0FBF71F9",
        "movswl  -7(%rcx), %esi",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "410FBF58F9",
        "movswl  -7(%r8), %ebx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "450FBF4AF9",
        "movswl  -7(%r10), %r9d",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WL, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "410FBF53F9",
        "movswl  -7(%r11), %edx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "480FBF71F9",
        "movswq  -7(%rcx), %rsi",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "490FBF58F9",
        "movswq  -7(%r8), %rbx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "4D0FBF4AF9",
        "movswq  -7(%r10), %r9",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::WQ, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "490FBF53F9",
        "movswq  -7(%r11), %rdx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, rcx), w_rsi),
        "486371F9",
        "movslq  -7(%rcx), %rsi",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, r8), w_rbx),
        "496358F9",
        "movslq  -7(%r8), %rbx",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, r10), w_r9),
        "4D634AF9",
        "movslq  -7(%r10), %r9",
    ));
    insns.push((
        i_MovSX_M_R(ExtMode::LQ, Addr::imm_reg(-7i32 as u32, r11), w_rdx),
        "496353F9",
        "movslq  -7(%r11), %rdx",
    ));

    // ========================================================
    // Mov_R_M.  Byte stores are tricky.  Check everything carefully.
    insns.push((
        i_Mov_R_M(8, rax, Addr::imm_reg(99, rdi)),
        "48894763",
        "movq    %rax, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(8, rbx, Addr::imm_reg(99, r8)),
        "49895863",
        "movq    %rbx, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(8, rcx, Addr::imm_reg(99, rsi)),
        "48894E63",
        "movq    %rcx, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(8, rdx, Addr::imm_reg(99, r9)),
        "49895163",
        "movq    %rdx, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(8, rsi, Addr::imm_reg(99, rax)),
        "48897063",
        "movq    %rsi, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(8, rdi, Addr::imm_reg(99, r15)),
        "49897F63",
        "movq    %rdi, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(8, rsp, Addr::imm_reg(99, rcx)),
        "48896163",
        "movq    %rsp, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(8, rbp, Addr::imm_reg(99, r14)),
        "49896E63",
        "movq    %rbp, 99(%r14)",
    ));
    insns.push((
        i_Mov_R_M(8, r8, Addr::imm_reg(99, rdi)),
        "4C894763",
        "movq    %r8, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(8, r9, Addr::imm_reg(99, r8)),
        "4D894863",
        "movq    %r9, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(8, r10, Addr::imm_reg(99, rsi)),
        "4C895663",
        "movq    %r10, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(8, r11, Addr::imm_reg(99, r9)),
        "4D895963",
        "movq    %r11, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(8, r12, Addr::imm_reg(99, rax)),
        "4C896063",
        "movq    %r12, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(8, r13, Addr::imm_reg(99, r15)),
        "4D896F63",
        "movq    %r13, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(8, r14, Addr::imm_reg(99, rcx)),
        "4C897163",
        "movq    %r14, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(8, r15, Addr::imm_reg(99, r14)),
        "4D897E63",
        "movq    %r15, 99(%r14)",
    ));
    //
    insns.push((
        i_Mov_R_M(4, rax, Addr::imm_reg(99, rdi)),
        "894763",
        "movl    %eax, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(4, rbx, Addr::imm_reg(99, r8)),
        "41895863",
        "movl    %ebx, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(4, rcx, Addr::imm_reg(99, rsi)),
        "894E63",
        "movl    %ecx, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(4, rdx, Addr::imm_reg(99, r9)),
        "41895163",
        "movl    %edx, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(4, rsi, Addr::imm_reg(99, rax)),
        "897063",
        "movl    %esi, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(4, rdi, Addr::imm_reg(99, r15)),
        "41897F63",
        "movl    %edi, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(4, rsp, Addr::imm_reg(99, rcx)),
        "896163",
        "movl    %esp, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(4, rbp, Addr::imm_reg(99, r14)),
        "41896E63",
        "movl    %ebp, 99(%r14)",
    ));
    insns.push((
        i_Mov_R_M(4, r8, Addr::imm_reg(99, rdi)),
        "44894763",
        "movl    %r8d, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(4, r9, Addr::imm_reg(99, r8)),
        "45894863",
        "movl    %r9d, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(4, r10, Addr::imm_reg(99, rsi)),
        "44895663",
        "movl    %r10d, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(4, r11, Addr::imm_reg(99, r9)),
        "45895963",
        "movl    %r11d, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(4, r12, Addr::imm_reg(99, rax)),
        "44896063",
        "movl    %r12d, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(4, r13, Addr::imm_reg(99, r15)),
        "45896F63",
        "movl    %r13d, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(4, r14, Addr::imm_reg(99, rcx)),
        "44897163",
        "movl    %r14d, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(4, r15, Addr::imm_reg(99, r14)),
        "45897E63",
        "movl    %r15d, 99(%r14)",
    ));
    //
    insns.push((
        i_Mov_R_M(2, rax, Addr::imm_reg(99, rdi)),
        "66894763",
        "movw    %ax, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(2, rbx, Addr::imm_reg(99, r8)),
        "6641895863",
        "movw    %bx, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(2, rcx, Addr::imm_reg(99, rsi)),
        "66894E63",
        "movw    %cx, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(2, rdx, Addr::imm_reg(99, r9)),
        "6641895163",
        "movw    %dx, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(2, rsi, Addr::imm_reg(99, rax)),
        "66897063",
        "movw    %si, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(2, rdi, Addr::imm_reg(99, r15)),
        "6641897F63",
        "movw    %di, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(2, rsp, Addr::imm_reg(99, rcx)),
        "66896163",
        "movw    %sp, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(2, rbp, Addr::imm_reg(99, r14)),
        "6641896E63",
        "movw    %bp, 99(%r14)",
    ));
    insns.push((
        i_Mov_R_M(2, r8, Addr::imm_reg(99, rdi)),
        "6644894763",
        "movw    %r8w, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(2, r9, Addr::imm_reg(99, r8)),
        "6645894863",
        "movw    %r9w, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(2, r10, Addr::imm_reg(99, rsi)),
        "6644895663",
        "movw    %r10w, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(2, r11, Addr::imm_reg(99, r9)),
        "6645895963",
        "movw    %r11w, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(2, r12, Addr::imm_reg(99, rax)),
        "6644896063",
        "movw    %r12w, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(2, r13, Addr::imm_reg(99, r15)),
        "6645896F63",
        "movw    %r13w, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(2, r14, Addr::imm_reg(99, rcx)),
        "6644897163",
        "movw    %r14w, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(2, r15, Addr::imm_reg(99, r14)),
        "6645897E63",
        "movw    %r15w, 99(%r14)",
    ));
    //
    insns.push((
        i_Mov_R_M(1, rax, Addr::imm_reg(99, rdi)),
        "884763",
        "movb    %al, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(1, rbx, Addr::imm_reg(99, r8)),
        "41885863",
        "movb    %bl, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(1, rcx, Addr::imm_reg(99, rsi)),
        "884E63",
        "movb    %cl, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(1, rdx, Addr::imm_reg(99, r9)),
        "41885163",
        "movb    %dl, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(1, rsi, Addr::imm_reg(99, rax)),
        "40887063",
        "movb    %sil, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(1, rdi, Addr::imm_reg(99, r15)),
        "41887F63",
        "movb    %dil, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(1, rsp, Addr::imm_reg(99, rcx)),
        "40886163",
        "movb    %spl, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(1, rbp, Addr::imm_reg(99, r14)),
        "41886E63",
        "movb    %bpl, 99(%r14)",
    ));
    insns.push((
        i_Mov_R_M(1, r8, Addr::imm_reg(99, rdi)),
        "44884763",
        "movb    %r8b, 99(%rdi)",
    ));
    insns.push((
        i_Mov_R_M(1, r9, Addr::imm_reg(99, r8)),
        "45884863",
        "movb    %r9b, 99(%r8)",
    ));
    insns.push((
        i_Mov_R_M(1, r10, Addr::imm_reg(99, rsi)),
        "44885663",
        "movb    %r10b, 99(%rsi)",
    ));
    insns.push((
        i_Mov_R_M(1, r11, Addr::imm_reg(99, r9)),
        "45885963",
        "movb    %r11b, 99(%r9)",
    ));
    insns.push((
        i_Mov_R_M(1, r12, Addr::imm_reg(99, rax)),
        "44886063",
        "movb    %r12b, 99(%rax)",
    ));
    insns.push((
        i_Mov_R_M(1, r13, Addr::imm_reg(99, r15)),
        "45886F63",
        "movb    %r13b, 99(%r15)",
    ));
    insns.push((
        i_Mov_R_M(1, r14, Addr::imm_reg(99, rcx)),
        "44887163",
        "movb    %r14b, 99(%rcx)",
    ));
    insns.push((
        i_Mov_R_M(1, r15, Addr::imm_reg(99, r14)),
        "45887E63",
        "movb    %r15b, 99(%r14)",
    ));

    // ========================================================
    // Shift_R
    insns.push((
        i_Shift_R(false, ShiftKind::Left, 0, w_rdi),
        "D3E7",
        "shll    %cl, %edi",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::Left, 0, w_r12),
        "41D3E4",
        "shll    %cl, %r12d",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::Left, 2, w_r8),
        "41C1E002",
        "shll    $2, %r8d",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::Left, 31, w_r13),
        "41C1E51F",
        "shll    $31, %r13d",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::Left, 0, w_r13),
        "49D3E5",
        "shlq    %cl, %r13",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::Left, 0, w_rdi),
        "48D3E7",
        "shlq    %cl, %rdi",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::Left, 2, w_r8),
        "49C1E002",
        "shlq    $2, %r8",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::Left, 3, w_rbx),
        "48C1E303",
        "shlq    $3, %rbx",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::Left, 63, w_r13),
        "49C1E53F",
        "shlq    $63, %r13",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::RightZ, 0, w_rdi),
        "D3EF",
        "shrl    %cl, %edi",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::RightZ, 2, w_r8),
        "41C1E802",
        "shrl    $2, %r8d",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::RightZ, 31, w_r13),
        "41C1ED1F",
        "shrl    $31, %r13d",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::RightZ, 0, w_rdi),
        "48D3EF",
        "shrq    %cl, %rdi",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::RightZ, 2, w_r8),
        "49C1E802",
        "shrq    $2, %r8",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::RightZ, 63, w_r13),
        "49C1ED3F",
        "shrq    $63, %r13",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::RightS, 0, w_rdi),
        "D3FF",
        "sarl    %cl, %edi",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::RightS, 2, w_r8),
        "41C1F802",
        "sarl    $2, %r8d",
    ));
    insns.push((
        i_Shift_R(false, ShiftKind::RightS, 31, w_r13),
        "41C1FD1F",
        "sarl    $31, %r13d",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::RightS, 0, w_rdi),
        "48D3FF",
        "sarq    %cl, %rdi",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::RightS, 2, w_r8),
        "49C1F802",
        "sarq    $2, %r8",
    ));
    insns.push((
        i_Shift_R(true, ShiftKind::RightS, 63, w_r13),
        "49C1FD3F",
        "sarq    $63, %r13",
    ));

    // ========================================================
    // Cmp_RMI_R
    insns.push((
        i_Cmp_RMI_R(8, RMI::reg(r15), rdx),
        "4C39FA",
        "cmpq    %r15, %rdx",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::reg(rcx), r8),
        "4939C8",
        "cmpq    %rcx, %r8",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::reg(rcx), rsi),
        "4839CE",
        "cmpq    %rcx, %rsi",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::mem(Addr::imm_reg(99, rdi)), rdx),
        "483B5763",
        "cmpq    99(%rdi), %rdx",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::mem(Addr::imm_reg(99, rdi)), r8),
        "4C3B4763",
        "cmpq    99(%rdi), %r8",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::mem(Addr::imm_reg(99, rdi)), rsi),
        "483B7763",
        "cmpq    99(%rdi), %rsi",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::imm(76543210), rdx),
        "4881FAEAF48F04",
        "cmpq    $76543210, %rdx",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::imm(-76543210i32 as u32), r8),
        "4981F8160B70FB",
        "cmpq    $-76543210, %r8",
    ));
    insns.push((
        i_Cmp_RMI_R(8, RMI::imm(76543210), rsi),
        "4881FEEAF48F04",
        "cmpq    $76543210, %rsi",
    ));
    //
    insns.push((
        i_Cmp_RMI_R(4, RMI::reg(r15), rdx),
        "4439FA",
        "cmpl    %r15d, %edx",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::reg(rcx), r8),
        "4139C8",
        "cmpl    %ecx, %r8d",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::reg(rcx), rsi),
        "39CE",
        "cmpl    %ecx, %esi",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::mem(Addr::imm_reg(99, rdi)), rdx),
        "3B5763",
        "cmpl    99(%rdi), %edx",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::mem(Addr::imm_reg(99, rdi)), r8),
        "443B4763",
        "cmpl    99(%rdi), %r8d",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::mem(Addr::imm_reg(99, rdi)), rsi),
        "3B7763",
        "cmpl    99(%rdi), %esi",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::imm(76543210), rdx),
        "81FAEAF48F04",
        "cmpl    $76543210, %edx",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::imm(-76543210i32 as u32), r8),
        "4181F8160B70FB",
        "cmpl    $-76543210, %r8d",
    ));
    insns.push((
        i_Cmp_RMI_R(4, RMI::imm(76543210), rsi),
        "81FEEAF48F04",
        "cmpl    $76543210, %esi",
    ));
    //
    insns.push((
        i_Cmp_RMI_R(2, RMI::reg(r15), rdx),
        "664439FA",
        "cmpw    %r15w, %dx",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::reg(rcx), r8),
        "664139C8",
        "cmpw    %cx, %r8w",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::reg(rcx), rsi),
        "6639CE",
        "cmpw    %cx, %si",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::mem(Addr::imm_reg(99, rdi)), rdx),
        "663B5763",
        "cmpw    99(%rdi), %dx",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::mem(Addr::imm_reg(99, rdi)), r8),
        "66443B4763",
        "cmpw    99(%rdi), %r8w",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::mem(Addr::imm_reg(99, rdi)), rsi),
        "663B7763",
        "cmpw    99(%rdi), %si",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::imm(23210), rdx),
        "6681FAAA5A",
        "cmpw    $23210, %dx",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::imm(-7654i32 as u32), r8),
        "664181F81AE2",
        "cmpw    $-7654, %r8w",
    ));
    insns.push((
        i_Cmp_RMI_R(2, RMI::imm(7654), rsi),
        "6681FEE61D",
        "cmpw    $7654, %si",
    ));
    //
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r15), rdx),
        "4438FA",
        "cmpb    %r15b, %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rcx), r8),
        "4138C8",
        "cmpb    %cl, %r8b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rcx), rsi),
        "4038CE",
        "cmpb    %cl, %sil",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::mem(Addr::imm_reg(99, rdi)), rdx),
        "3A5763",
        "cmpb    99(%rdi), %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::mem(Addr::imm_reg(99, rdi)), r8),
        "443A4763",
        "cmpb    99(%rdi), %r8b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::mem(Addr::imm_reg(99, rdi)), rsi),
        "403A7763",
        "cmpb    99(%rdi), %sil",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::imm(70), rdx),
        "80FA46",
        "cmpb    $70, %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::imm(-76i32 as u32), r8),
        "4180F8B4",
        "cmpb    $-76, %r8b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::imm(76), rsi),
        "4080FE4C",
        "cmpb    $76, %sil",
    ));
    // Extra byte-cases (paranoia!) for Cmp_RMI_R for first operand = R
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rax), rbx),
        "38C3",
        "cmpb    %al, %bl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rbx), rax),
        "38D8",
        "cmpb    %bl, %al",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rcx), rdx),
        "38CA",
        "cmpb    %cl, %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rcx), rsi),
        "4038CE",
        "cmpb    %cl, %sil",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rcx), r10),
        "4138CA",
        "cmpb    %cl, %r10b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rcx), r14),
        "4138CE",
        "cmpb    %cl, %r14b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rbp), rdx),
        "4038EA",
        "cmpb    %bpl, %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rbp), rsi),
        "4038EE",
        "cmpb    %bpl, %sil",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rbp), r10),
        "4138EA",
        "cmpb    %bpl, %r10b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(rbp), r14),
        "4138EE",
        "cmpb    %bpl, %r14b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r9), rdx),
        "4438CA",
        "cmpb    %r9b, %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r9), rsi),
        "4438CE",
        "cmpb    %r9b, %sil",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r9), r10),
        "4538CA",
        "cmpb    %r9b, %r10b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r9), r14),
        "4538CE",
        "cmpb    %r9b, %r14b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r13), rdx),
        "4438EA",
        "cmpb    %r13b, %dl",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r13), rsi),
        "4438EE",
        "cmpb    %r13b, %sil",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r13), r10),
        "4538EA",
        "cmpb    %r13b, %r10b",
    ));
    insns.push((
        i_Cmp_RMI_R(1, RMI::reg(r13), r14),
        "4538EE",
        "cmpb    %r13b, %r14b",
    ));

    // ========================================================
    // Push64
    insns.push((i_Push64(RMI::reg(rdi)), "57", "pushq   %rdi"));
    insns.push((i_Push64(RMI::reg(r8)), "4150", "pushq   %r8"));
    insns.push((
        i_Push64(RMI::mem(Addr::imm_reg_reg_shift(321, rsi, rcx, 3))),
        "FFB4CE41010000",
        "pushq   321(%rsi,%rcx,8)",
    ));
    insns.push((
        i_Push64(RMI::mem(Addr::imm_reg_reg_shift(321, r9, rbx, 2))),
        "41FFB49941010000",
        "pushq   321(%r9,%rbx,4)",
    ));
    insns.push((i_Push64(RMI::imm(0)), "6A00", "pushq   $0"));
    insns.push((i_Push64(RMI::imm(127)), "6A7F", "pushq   $127"));
    insns.push((i_Push64(RMI::imm(128)), "6880000000", "pushq   $128"));
    insns.push((
        i_Push64(RMI::imm(0x31415927)),
        "6827594131",
        "pushq   $826366247",
    ));
    insns.push((i_Push64(RMI::imm(-128i32 as u32)), "6A80", "pushq   $-128"));
    insns.push((
        i_Push64(RMI::imm(-129i32 as u32)),
        "687FFFFFFF",
        "pushq   $-129",
    ));
    insns.push((
        i_Push64(RMI::imm(-0x75c4e8a1i32 as u32)),
        "685F173B8A",
        "pushq   $-1975838881",
    ));

    // ========================================================
    // Pop64
    insns.push((i_Pop64(w_rax), "58", "popq    %rax"));
    insns.push((i_Pop64(w_rdi), "5F", "popq    %rdi"));
    insns.push((i_Pop64(w_r8), "4158", "popq    %r8"));
    insns.push((i_Pop64(w_r15), "415F", "popq    %r15"));

    // ========================================================
    // CallKnown skipped for now

    // ========================================================
    // CallUnknown
    insns.push((i_CallUnknown(RM::reg(rbp)), "FFD5", "call    *%rbp"));
    insns.push((i_CallUnknown(RM::reg(r11)), "41FFD3", "call    *%r11"));
    insns.push((
        i_CallUnknown(RM::mem(Addr::imm_reg_reg_shift(321, rsi, rcx, 3))),
        "FF94CE41010000",
        "call    *321(%rsi,%rcx,8)",
    ));
    insns.push((
        i_CallUnknown(RM::mem(Addr::imm_reg_reg_shift(321, r10, rdx, 2))),
        "41FF949241010000",
        "call    *321(%r10,%rdx,4)",
    ));

    // ========================================================
    // Ret
    insns.push((i_Ret(), "C3", "ret"));

    // ========================================================
    // JmpKnown skipped for now

    // ========================================================
    // JmpCondSymm isn't a real instruction

    // ========================================================
    // JmpCond skipped for now

    // ========================================================
    // JmpCondCompound isn't a real instruction

    // ========================================================
    // JmpUnknown
    insns.push((i_JmpUnknown(RM::reg(rbp)), "FFE5", "jmp     *%rbp"));
    insns.push((i_JmpUnknown(RM::reg(r11)), "41FFE3", "jmp     *%r11"));
    insns.push((
        i_JmpUnknown(RM::mem(Addr::imm_reg_reg_shift(321, rsi, rcx, 3))),
        "FFA4CE41010000",
        "jmp     *321(%rsi,%rcx,8)",
    ));
    insns.push((
        i_JmpUnknown(RM::mem(Addr::imm_reg_reg_shift(321, r10, rdx, 2))),
        "41FFA49241010000",
        "jmp     *321(%r10,%rdx,4)",
    ));

    // ========================================================
    // Actually run the tests!
    let rru = create_reg_universe_systemv(CallConv::Fast);
    for (insn, expected_encoding, expected_printing) in insns {
        // Check the printed text is as expected.
        let actual_printing = insn.show_rru(Some(&rru));
        assert_eq!(expected_printing, actual_printing);

        // Check the encoding is as expected.
        let text_size = {
            let mut code_sec = MachSectionSize::new(0);
            insn.emit(&mut code_sec);
            code_sec.size()
        };

        let mut sink = test_utils::TestCodeSink::new();
        let mut sections = MachSections::new();
        let code_idx = sections.add_section(0, text_size);
        let code_sec = sections.get_section(code_idx);
        insn.emit(code_sec);
        sections.emit(&mut sink);
        let actual_encoding = &sink.stringify();
        assert_eq!(expected_encoding, actual_encoding);
    }
}
