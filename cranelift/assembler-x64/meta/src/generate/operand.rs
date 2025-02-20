use crate::dsl;
use crate::dsl::format::RegKind::*;

impl dsl::Operand {
    #[must_use]
    pub fn generate_type(&self) -> Option<String> {
        use dsl::OperandKind::*;
        match (self.location.kind(), self.location.reg_kind()) {
            (Imm(loc), _) => Some(format!("Imm{}", loc.bits())),
            (Reg(_), Gpr(_)) => Some(format!("Gpr<R::{}Gpr>", self.mutability.generate_type())),
            (RegMem(_), Gpr(_)) => {
                Some(format!("GprMem<R::{}Gpr, R::ReadGpr>", self.mutability.generate_type()))
            }
            (Reg(_), Vec(_)) => Some(format!("Vec<R::{}Vec>", self.mutability.generate_type())),
            (RegMem(_), Vec(_)) => {
                Some(format!("VecMem<R::{}Vec, R::ReadVec>", self.mutability.generate_type()))
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn generate_mut_ty(&self, read_ty: &str, read_write_ty: &str, write_ty: &str) -> Option<String> {
        use dsl::Mutability::*;
        use dsl::OperandKind::*;
        let pick_ty = match self.mutability {
            Read => read_ty,
            ReadWrite => read_write_ty,
            Write => write_ty,
        };
        match self.location.kind() {
            FixedReg(_) => None,
            Imm(loc) => Some(format!("Imm{}", loc.bits())),
            Reg(_) => Some(format!("Gpr<{pick_ty}>")),
            RegMem(_) => Some(format!("GprMem<{pick_ty}, {read_ty}>")),
        }
    }
}

impl dsl::Location {
    /// `<operand type>`, if the operand has a type (i.e., not fixed registers).
    #[must_use]
    pub fn generate_type(&self, generic: Option<String>) -> Option<String> {
        use dsl::Location::*;
        let generic = match generic {
            Some(ty) => format!("<{ty}>"),
            None => String::new(),
        };
        match self {
            al | ax | eax | rax => None,
            imm8 => Some("Imm8".into()),
            imm16 => Some("Imm16".into()),
            imm32 => Some("Imm32".into()),
            r8 | r16 | r32 | r64 => Some(format!("Gpr{generic}")),
            rm8 | rm16 | rm32 | rm64 => Some(format!("GprMem{generic}")),
            xmm1 | xmm2 | ymm1 | ymm2 => Some(format!("Vec{generic}")),
            xmm3m128 | ymm3m256 => Some(format!("VecMem{generic}")),
        }
    }

    /// `self.<operand>.to_string(...)`
    #[must_use]
    pub fn generate_to_string(&self, extension: dsl::Extension) -> String {
        use dsl::Location::*;
        match self {
            al => "\"%al\"".into(),
            ax => "\"%ax\"".into(),
            eax => "\"%eax\"".into(),
            rax => "\"%rax\"".into(),
            imm8 | imm16 | imm32 => {
                let variant = extension.generate_variant();
                format!("self.{self}.to_string({variant})")
            }
            r8 | r16 | r32 | r64 | rm8 | rm16 | rm32 | rm64 => match self.generate_size() {
                Some(size) => format!("self.{self}.to_string({size})"),
                None => unreachable!(),
            },
            xmm1 | xmm2 | xmm3m128 | ymm1 | ymm2 | ymm3m256 => match self.generate_size() {
                Some(size) => format!("self.{self}.to_string({size})"),
                None => unreachable!(),
            },
        }
    }

    /// `Size::<operand size>`
    #[must_use]
    pub fn generate_size(&self) -> Option<&str> {
        use dsl::Location::*;
        match self {
            al | ax | eax | rax | imm8 | imm16 | imm32 => None,
            r8 | rm8 => Some("Size::Byte"),
            r16 | rm16 => Some("Size::Word"),
            r32 | rm32 => Some("Size::Doubleword"),
            r64 | rm64 => Some("Size::Quadword"),
            xmm1 | xmm2 | xmm3m128 => Some("Size::Octoword"),
            ymm1 | ymm2 | ymm3m256 => Some("Size::DoubleOctoword"),
        }
    }

    /// `Gpr(regs::...)`
    #[must_use]
    pub fn generate_fixed_reg(&self) -> Option<&str> {
        use dsl::Location::*;
        match self {
            al | ax | eax | rax => Some("reg::enc::RAX"),
            imm8 | imm16 | imm32 | r8 | r16 | r32 | r64 | rm8 | rm16 | rm32 | rm64 | xmm1 | xmm2
            | xmm3m128 | ymm1 | ymm2 | ymm3m256 => None,
        }
    }
}

impl dsl::Mutability {
    #[must_use]
    pub fn generate_regalloc_call(&self) -> &str {
        match self {
            dsl::Mutability::Read => "read",
            dsl::Mutability::ReadWrite => "read_write",
            dsl::Mutability::Write => "write",
        }
    }

    #[must_use]
    pub fn generate_type(&self) -> &str {
        match self {
            dsl::Mutability::Read => "Read",
            dsl::Mutability::ReadWrite => "ReadWrite",
            dsl::Mutability::Write => "Write",
        }
    }
}

impl dsl::Extension {
    /// `Extension::...`
    #[must_use]
    pub fn generate_variant(&self) -> &str {
        use dsl::Extension::*;
        match self {
            None => "Extension::None",
            SignExtendWord => "Extension::SignExtendWord",
            SignExtendLong => "Extension::SignExtendLong",
            SignExtendQuad => "Extension::SignExtendQuad",
            ZeroExtend => "Extension::ZeroExtend",
        }
    }
}
