//! Generate format-related Rust code; this also includes generation of encoding
//! Rust code.

use super::{fmtln, Formatter};
use crate::dsl;

impl dsl::Format {
    /// Re-order the Intel-style operand order to accommodate ATT-style
    /// printing.
    ///
    /// This is an unfortunate necessity to match Cranelift's current
    /// disassembly, which uses AT&T-style printing. The plan is to eventually
    /// transition to Intel-style printing (and avoid this awkward reordering)
    /// once Cranelift has switched to using this assembler predominantly
    /// (TODO).
    #[must_use]
    pub fn generate_att_style_operands(&self) -> String {
        let ordered_ops: Vec<_> = self
            .operands
            .iter()
            .rev()
            .map(|o| format!("{{{}}}", o.location))
            .collect();
        ordered_ops.join(", ")
    }

    pub fn generate_rex_encoding(&self, f: &mut Formatter, rex: &dsl::Rex) {
        self.generate_prefixes(f, rex);
        self.generate_rex_prefix(f, rex);
        self.generate_opcodes(f, rex);
        self.generate_modrm_byte(f, rex);
        self.generate_immediate(f);
    }

    pub fn generate_vex_encoding(&self, f: &mut Formatter, vex: &dsl::Vex) {
        //self.generate_prefix(f, vex);
        self.generate_vex_prefix(f, vex);
        //self.generate_opcodes(f, vex);
        //self.generate_modrm_byte(f, vex);
        self.generate_immediate(f);
    }

    /// `buf.put1(...);`
    fn generate_prefixes(&self, f: &mut Formatter, rex: &dsl::Rex) {
        if !rex.opcodes.prefixes.is_empty() {
            f.empty_line();
            f.comment("Emit prefixes.");
        }
        if let Some(group1) = &rex.opcodes.prefixes.group1 {
            fmtln!(f, "buf.put1({group1});");
        }
        if let Some(group2) = &rex.opcodes.prefixes.group2 {
            fmtln!(f, "buf.put1({group2});");
        }
        if let Some(group3) = &rex.opcodes.prefixes.group3 {
            fmtln!(f, "buf.put1({group3});");
        }
        if let Some(group4) = &rex.opcodes.prefixes.group4 {
            fmtln!(f, "buf.put1({group4});");
        }
    }

    // `buf.put1(...);`
    fn generate_opcodes(&self, f: &mut Formatter, rex: &dsl::Rex) {
        f.empty_line();
        f.comment("Emit opcode(s).");
        if rex.opcodes.escape {
            fmtln!(f, "buf.put1(0x0f);");
        }
        fmtln!(f, "buf.put1(0x{:x});", rex.opcodes.primary);
        if let Some(secondary) = rex.opcodes.secondary {
            fmtln!(f, "buf.put1(0x{:x});", secondary);
        }
    }

    fn generate_rex_prefix(&self, f: &mut Formatter, rex: &dsl::Rex) {
        use dsl::OperandKind::{FixedReg, Imm, Mem, Reg, RegMem};
        f.empty_line();
        f.comment("Emit REX prefix.");

        let find_8bit_registers = |l: &dsl::Location| l.bits() == 8 && matches!(l.kind(), Reg(_) | RegMem(_));
        if self.locations().any(find_8bit_registers) {
            fmtln!(f, "let mut rex = {};", rex.generate_flags());
            for op in self.locations().copied().filter(find_8bit_registers) {
                fmtln!(f, "self.{op}.always_emit_if_8bit_needed(&mut rex);");
            }
        } else {
            fmtln!(f, "let rex = {};", rex.generate_flags());
        }

        match self.operands_by_kind().as_slice() {
            [FixedReg(dst), Imm(_)] => {
                // TODO: don't emit REX byte here.
                fmtln!(f, "let {dst} = {};", dst.generate_fixed_reg().unwrap());
                assert_eq!(rex.digit, None, "we expect no digit for operands: [FixedReg, Imm]");
                fmtln!(f, "let digit = 0;");
                fmtln!(f, "rex.emit_two_op(buf, digit, {dst}.enc());");
            }
            [Mem(dst), Imm(_)] => {
                let digit = rex.digit.expect("REX digit must be set for operands: [Mem, Imm]");
                fmtln!(f, "let digit = 0x{digit:x};");
                fmtln!(f, "self.{dst}.emit_rex_prefix(rex, digit, buf);");
            }
            [RegMem(dst), Imm(_)] => {
                let digit = rex.digit.expect("REX digit must be set for operands: [RegMem, Imm]");
                fmtln!(f, "let digit = 0x{digit:x};");
                f.add_block(&format!("match &self.{dst}"), |f| {
                    fmtln!(f, "GprMem::Gpr({dst}) => rex.emit_two_op(buf, digit, {dst}.enc()),");
                    fmtln!(f, "GprMem::Mem({dst}) => {dst}.emit_rex_prefix(rex, digit, buf),");
                });
            }
            [Reg(dst), RegMem(src)] => {
                fmtln!(f, "let {dst} = self.{dst}.enc();");
                f.add_block(&format!("match &self.{src}"), |f| {
                    match dst.bits() {
                        128 => {
                            fmtln!(f, "XmmMem::Xmm({src}) => rex.emit_two_op(buf, {dst}, {src}.enc()),");
                            fmtln!(f, "XmmMem::Mem({src}) => {src}.emit_rex_prefix(rex, {dst}, buf),");
                        }
                        _ => {
                            fmtln!(f, "GprMem::Gpr({src}) => rex.emit_two_op(buf, {dst}, {src}.enc()),");
                            fmtln!(f, "GprMem::Mem({src}) => {src}.emit_rex_prefix(rex, {dst}, buf),");
                        }
                    };
                });
            }
            [Mem(dst), Reg(src)] => {
                fmtln!(f, "let {src} = self.{src}.enc();");
                fmtln!(f, "self.{dst}.emit_rex_prefix(rex, {src}, buf);");
            }
            [RegMem(dst), Reg(src)] | [RegMem(dst), Reg(src), Imm(_)] | [RegMem(dst), Reg(src), FixedReg(_)] => {
                fmtln!(f, "let {src} = self.{src}.enc();");
                f.add_block(&format!("match &self.{dst}"), |f| match src.bits() {
                    128 => {
                        fmtln!(f, "XmmMem::Xmm({dst}) => rex.emit_two_op(buf, {src}, {dst}.enc()),");
                        fmtln!(f, "XmmMem::Mem({dst}) => {dst}.emit_rex_prefix(rex, {src}, buf),");
                    }
                    _ => {
                        fmtln!(f, "GprMem::Gpr({dst}) => rex.emit_two_op(buf, {src}, {dst}.enc()),");
                        fmtln!(f, "GprMem::Mem({dst}) => {dst}.emit_rex_prefix(rex, {src}, buf),");
                    }
                });
            }

            unknown => unimplemented!("unknown pattern: {unknown:?}"),
        }
    }

    fn generate_vex_prefix(&self, f: &mut Formatter, vex: &dsl::Vex) {
        use dsl::OperandKind::{FixedReg, Imm, Reg, RegMem};
        f.empty_line();
        f.comment("Emit VEX prefix.");

        // Create a vex struct
        fmtln!(f, "let mut vex = new_vex({});", vex.opcodes.primary);

        // 2/3 byte prefix
        //if b_bit(vex) && x_bit(vex) {
        if false {
            fmtln!(f, "// 2 byte prefix");
            //fmtln!(f, "buf.put1(0xC5);");
            fmtln!(f, "encode_2byte_prefix(&vex, buf)");
        } else {
            fmtln!(f, "// 3 byte prefix");
            fmtln!(f, "encode_3byte_prefix(&vex, buf)");
            //fmtln!(f, "buf.put1(0xC4);");
            //fmtln!(f, "vex.encode_3byte_prefix");
        }

        /*
        let find_8bit_registers = |l: &dsl::Location| l.bits() == 8 && matches!(l.kind(), Reg(_) | RegMem(_));
        if self.locations().any(find_8bit_registers) {
            fmtln!(f, "let mut vex = {};", vex.generate_flags());
            for op in self.locations().copied().filter(find_8bit_registers) {
                fmtln!(f, "self.{op}.always_emit_if_8bit_needed(&mut vex);");
            }
        } else {
            fmtln!(f, "let vex = {};", vex.generate_flags());
        }
        */

        match self.operands_by_kind().as_slice() {
            [Reg(xmm1), Reg(xmm2), RegMem(xmm_m128)] => {
                //fmtln!(f, "let {xmm1} = self.{xmm1}.enc();");
                //fmtln!(f, "let {xmm2} = self.{xmm2}.enc();");
                //fmtln!(f, "let {xmm_m128} = self.{xmm_m128}.enc();");
                //fmtln!(f, "vex.emit_three_op(buf, {xmm1}, {xmm2}, {xmm_m128});");
            }
            /*
            [FixedReg(dst), Imm(_)] => {

                // TODO: don't emit VEX byte here.
                fmtln!(f, "let {dst} = {};", dst.generate_fixed_reg().unwrap());
                assert_eq!(vex.digit, None, "we expect no digit for operands: [FixedReg, Imm]");
                fmtln!(f, "let digit = 0;");
                fmtln!(f, "vex.emit_two_op(buf, digit, {dst}.enc());");

            }
            [RegMem(dst), Imm(_)] => {

                let digit = vex
                    .digit
                    .expect("vex digit must be set for operands: [RegMem, Imm]");
                fmtln!(f, "let digit = 0x{digit:x};");
                f.add_block(&format!("match &self.{dst}"), |f| {
                    fmtln!(f, "GprMem::Gpr({dst}) => vex.emit_two_op(buf, digit, {dst}.enc()),");
                    fmtln!(f, "GprMem::Mem({dst}) => {dst}.emit_vex_prefix(vex, digit, buf),");
                });

            }
            [Reg(dst), RegMem(src)] => {
                fmtln!(f, "let {dst} = self.{dst}.enc();");
                f.add_block(&format!("match &self.{src}"), |f| {
                    match dst.bits() {
                        128 => {
                            fmtln!(f, "XmmMem::Xmm({src}) => vex.emit_two_op(buf, {dst}, {src}.enc()),");
                            fmtln!(f, "XmmMem::Mem({src}) => {src}.emit_vex_prefix(vex, {dst}, buf),");
                        }
                        _ => {
                            fmtln!(f, "GprMem::Gpr({src}) => vex.emit_two_op(buf, {dst}, {src}.enc()),");
                            fmtln!(f, "GprMem::Mem({src}) => {src}.emit_vex_prefix(vex, {dst}, buf),");
                        }
                    };
                });
            }
            [RegMem(dst), Reg(src)]
            | [RegMem(dst), Reg(src), Imm(_)]
            | [RegMem(dst), Reg(src), FixedReg(_)] => {
                fmtln!(f, "let {src} = self.{src}.enc();");
                f.add_block(&format!("match &self.{dst}"), |f| match src.bits() {
                    128 => {
                        fmtln!(f, "XmmMem::Xmm({dst}) => vex.emit_two_op(buf, {src}, {dst}.enc()),");
                        fmtln!(f, "XmmMem::Mem({dst}) => {dst}.emit_vex_prefix(vex, {src}, buf),");
                    }
                    _ => {
                        fmtln!(f, "GprMem::Gpr({dst}) => vex.emit_two_op(buf, {src}, {dst}.enc()),");
                        fmtln!(f, "GprMem::Mem({dst}) => {dst}.emit_vex_prefix(vex, {src}, buf),");
                    }
                });

            }
            */
            unknown => unimplemented!("unknown pattern: {unknown:?}"),
        }
    }

    fn generate_modrm_byte(&self, f: &mut Formatter, rex: &dsl::Rex) {
        use dsl::OperandKind::{FixedReg, Imm, Mem, Reg, RegMem};

        if let [FixedReg(_), Imm(_)] = self.operands_by_kind().as_slice() {
            // No need to emit a comment.
        } else {
            f.empty_line();
            f.comment("Emit ModR/M byte.");
        }

        match self.operands_by_kind().as_slice() {
            [FixedReg(_), Imm(_)] => {
                // No need to emit a ModRM byte: we know the register used.
            }
            [Mem(dst), Imm(_)] => {
                let digit = rex.digit.expect("REX digit must be set for operands: [RegMem, Imm]");
                fmtln!(f, "let digit = 0x{digit:x};");
                fmtln!(f, "emit_modrm_sib_disp(buf, off, digit, &self.{dst}, 0, None);");
            }
            [RegMem(dst), Imm(_)] => {
                let digit = rex.digit.expect("REX digit must be set for operands: [RegMem, Imm]");
                fmtln!(f, "let digit = 0x{digit:x};");
                f.add_block(&format!("match &self.{dst}"), |f| {
                    fmtln!(f, "GprMem::Gpr({dst}) => emit_modrm(buf, digit, {dst}.enc()),");
                    fmtln!(f, "GprMem::Mem({dst}) => emit_modrm_sib_disp(buf, off, digit, {dst}, 0, None),");
                });
            }
            [Reg(dst), RegMem(src)] => {
                fmtln!(f, "let {dst} = self.{dst}.enc();");
                f.add_block(&format!("match &self.{src}"), |f| {
                    match dst.bits() {
                        128 => {
                            fmtln!(f, "XmmMem::Xmm({src}) => emit_modrm(buf, {dst}, {src}.enc()),");
                            fmtln!(f, "XmmMem::Mem({src}) => emit_modrm_sib_disp(buf, off, {dst}, {src}, 0, None),");
                        }
                        _ => {
                            fmtln!(f, "GprMem::Gpr({src}) => emit_modrm(buf, {dst}, {src}.enc()),");
                            fmtln!(f, "GprMem::Mem({src}) => emit_modrm_sib_disp(buf, off, {dst}, {src}, 0, None),");
                        }
                    };
                });
            }
            [Mem(dst), Reg(src)] => {
                fmtln!(f, "let {src} = self.{src}.enc();");
                fmtln!(f, "emit_modrm_sib_disp(buf, off, {src}, &self.{dst}, 0, None);");
            }
            [RegMem(dst), Reg(src)] | [RegMem(dst), Reg(src), Imm(_)] | [RegMem(dst), Reg(src), FixedReg(_)] => {
                fmtln!(f, "let {src} = self.{src}.enc();");
                f.add_block(&format!("match &self.{dst}"), |f| {
                    match src.bits() {
                        128 => {
                            fmtln!(f, "XmmMem::Xmm({dst}) => emit_modrm(buf, {src}, {dst}.enc()),");
                            fmtln!(f, "XmmMem::Mem({dst}) => emit_modrm_sib_disp(buf, off, {src}, {dst}, 0, None),");
                        }
                        _ => {
                            fmtln!(f, "GprMem::Gpr({dst}) => emit_modrm(buf, {src}, {dst}.enc()),");
                            fmtln!(f, "GprMem::Mem({dst}) => emit_modrm_sib_disp(buf, off, {src}, {dst}, 0, None),");
                        }
                    };
                });
            }
            unknown => unimplemented!("unknown pattern: {unknown:?}"),
        }
    }

    fn generate_immediate(&self, f: &mut Formatter) {
        use dsl::OperandKind::Imm;
        match self.operands_by_kind().as_slice() {
            [prefix @ .., Imm(imm)] => {
                assert!(!prefix.iter().any(|o| matches!(o, Imm(_))));

                f.empty_line();
                f.comment("Emit immediate.");
                fmtln!(f, "self.{imm}.encode(buf);");
            }
            unknown => {
                // Do nothing: no immediates expected.
                assert!(!unknown.iter().any(|o| matches!(o, Imm(_))));
            }
        }
    }
}

impl dsl::Rex {
    fn generate_flags(&self) -> &str {
        if self.w {
            "RexFlags::set_w()"
        } else {
            "RexFlags::clear_w()"
        }
    }
}
