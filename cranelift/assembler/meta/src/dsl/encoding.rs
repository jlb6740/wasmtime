use super::{Operand, OperandKind};
use core::fmt;

/// Abbreviated constructor for REX-encoded instructions.
#[must_use]
pub fn rex(opcode: u8) -> Rex {
    Rex {
        prefixes: LegacyPrefixes::NoPrefix,
        opcode,
        w: false,
        r: false,
        digit: 0,
        imm: Imm::None,
    }
}

/// Abbreviated constructor for VEX-encoded instructions.
#[must_use]
pub fn vex(opcode: u8) -> Vex {
    Vex {
        opcode,
        w: false,
        r: false,
        digit: 0,
        imm: Imm::None,
        is4: false,
        sizeE: 0,
        wig: false,
        rxb: 0,
        length: VexLength::_128,
        mmmmm: VexMMMMM::_OF,
        pp: VexPP::None,
    }
}

pub enum Encoding {
    Rex(Rex),
    Vex(Vex),
}
impl Encoding {
    pub fn validate(&self, operands: &[Operand]) {
        match self {
            Encoding::Rex(rex) => rex.validate(operands),
            Encoding::Vex(vex) => vex.validate(operands),
        }
    }

    pub fn has_legacy_prefixes(&self) {}
}
impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Encoding::Rex(rex) => write!(f, "{rex}"),
            Encoding::Vex(vex) => write!(f, "{vex}"),
        }
    }
}

pub struct Rex {
    /// Any legacy prefixes that should be included with the instruction.
    pub prefixes: LegacyPrefixes,
    /// The opcode of the instruction.
    pub opcode: u8,
    /// Indicates setting the REX.W bit.
    ///
    /// From the specification: "Indicates the use of a REX prefix that affects
    /// operand size or instruction semantics. The ordering of the REX prefix
    /// and other optional/mandatory instruction prefixes are discussed Chapter
    /// 2. Note that REX prefixes that promote legacy instructions to 64-bit
    /// behavior are not listed explicitly in the opcode column."
    pub w: bool,
    /// From the specification: "indicates that the ModR/M byte of the
    /// instruction contains a register operand and an r/m operand."
    pub r: bool,
    /// From the specification: "a digit between 0 and 7 indicates that the
    /// ModR/M byte of the instruction uses only the r/m (register or memory)
    /// operand. The reg field contains the digit that provides an extension to
    /// the instruction's opcode."
    pub digit: u8,
    /// The number of bits used as an immediate operand to the instruction.
    ///
    /// From the specification: "a 1-byte (ib), 2-byte (iw), 4-byte (id) or
    /// 8-byte (io) immediate operand to the instruction that follows the
    /// opcode, ModR/M bytes or scale-indexing bytes. The opcode determines if
    /// the operand is a signed value. All words, doublewords, and quadwords are
    /// given with the low-order byte first."
    pub imm: Imm,
}

impl Rex {
    #[must_use]
    pub fn prefix(self, prefixes: LegacyPrefixes) -> Self {
        Self { prefixes, ..self }
    }

    #[must_use]
    pub fn w(self) -> Self {
        Self { w: true, ..self }
    }
    #[must_use]
    pub fn r(self) -> Self {
        Self { r: true, ..self }
    }
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn digit(self, digit: u8) -> Self {
        assert!(digit < 8);
        Self { digit, ..self }
    }

    #[must_use]
    pub fn ib(self) -> Self {
        Self { imm: Imm::ib, ..self }
    }
    #[must_use]
    pub fn iw(self) -> Self {
        Self { imm: Imm::iw, ..self }
    }
    #[must_use]
    pub fn id(self) -> Self {
        Self { imm: Imm::id, ..self }
    }
    #[must_use]
    pub fn io(self) -> Self {
        Self { imm: Imm::io, ..self }
    }

    fn validate(&self, operands: &[Operand]) {
        assert!(self.digit < 8);
        assert!(!(self.r && self.digit > 0));
        assert!(!(self.r && self.imm != Imm::None));
        assert!(
            !(self.w && (self.prefixes.contains_66())),
            "though valid, if REX.W is set then the 66 prefix is ignored--avoid encoding this"
        );
        // assert!(self.prefixes.contains_66() && operands.iter().all(|&op| op == 16));

        if let Some(OperandKind::Imm(op)) = operands
            .iter()
            .map(|o| o.location.kind())
            .find(|k| matches!(k, OperandKind::Imm(_)))
        {
            assert_eq!(op.bits(), self.imm.bits());
        }
    }
}
impl From<Rex> for Encoding {
    fn from(rex: Rex) -> Encoding {
        Encoding::Rex(rex)
    }
}
impl fmt::Display for Rex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.prefixes {
            LegacyPrefixes::NoPrefix => {}
            LegacyPrefixes::_66 => write!(f, "0x66 + ")?,
            LegacyPrefixes::_F0 => write!(f, "0xF0 + ")?,
            LegacyPrefixes::_66F0 => write!(f, "0x66F0 + ")?,
            LegacyPrefixes::_F2 => write!(f, "0xF2 + ")?,
            LegacyPrefixes::_F3 => write!(f, "0xF3 + ")?,
            LegacyPrefixes::_66F3 => write!(f, "0x66F3 + ")?,
        }
        if self.w {
            write!(f, "REX.W + ")?;
        }
        write!(f, "{:#04x}", self.opcode)?;
        if self.r {
            write!(f, " /r")?;
        }
        if self.digit > 0 {
            write!(f, " /{}", self.digit)?;
        }
        if self.imm != Imm::None {
            write!(f, " {}", self.imm)?;
        }
        Ok(())
    }
}

#[derive(PartialEq)]
pub enum LegacyPrefixes {
    /// No prefix bytes.
    NoPrefix,
    /// Operand size override -- here, denoting "16-bit operation".
    _66,
    /// The lock prefix.
    _F0,
    /// Operand size override and lock.
    _66F0,
    /// REPNE, but no specific meaning here -- is just an opcode extension.
    _F2,
    /// REP/REPE, but no specific meaning here -- is just an opcode extension.
    _F3,
    /// Operand size override and same effect as F3.
    _66F3,
}
impl LegacyPrefixes {
    #[must_use]
    pub fn contains_66(&self) -> bool {
        match self {
            LegacyPrefixes::_66 | LegacyPrefixes::_66F0 | LegacyPrefixes::_66F3 => true,
            LegacyPrefixes::NoPrefix
            | LegacyPrefixes::_F0
            | LegacyPrefixes::_F2
            | LegacyPrefixes::_F3 => false,
        }
    }
}

#[derive(PartialEq)]
#[allow(non_camel_case_types)]
pub enum Imm {
    None,
    ib,
    iw,
    id,
    io,
}
impl Imm {
    fn bits(&self) -> u16 {
        match self {
            Imm::None => 0,
            Imm::ib => 8,
            Imm::iw => 16,
            Imm::id => 32,
            Imm::io => 64,
        }
    }
}
impl fmt::Display for Imm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Imm::None => write!(f, ""),
            Imm::ib => write!(f, "ib"),
            Imm::iw => write!(f, "iw"),
            Imm::id => write!(f, "id"),
            Imm::io => write!(f, "io"),
        }
    }
}

pub struct Vex {
    /// Any legacy prefixes that should be included with the instruction.
    //pub prefix: LegacyPrefixes,

    ///VEX bit field:  Value of false (0) means length is scalar or 128 bits while true (1) means 256 bits.
    pub length: VexLength,

    /// VEX bit field: Opcode extension providing equivalent functionality of a SIMD prefix.
    pub pp: VexPP,

    pub mmmmm: VexMMMMM,

    /// TODO: Maybe can delete. Placeholder for OF, OF3A, and OF3B
    pub sizeE: u8,

    pub wig: bool,

    pub is4: bool,

    pub rxb: u8,

    /// Vector Length Encoding (VEX) prefix.
    //pub VEX: u16,

    /// The opcode of the instruction.
    pub opcode: u8,
    /// Indicates setting the VEX.W bit.
    ///
    /// From the specification: "Indicates the use of a REX prefix that affects
    /// operand size or instruction semantics. The ordering of the REX prefix
    /// and other optional/mandatory instruction prefixes are discussed Chapter
    /// 2. Note that REX prefixes that promote legacy instructions to 64-bit
    /// behavior are not listed explicitly in the opcode column."
    pub w: bool,
    /// From the specification: "indicates that the ModR/M byte of the
    /// instruction contains a register operand and an r/m operand."
    pub r: bool,
    /// From the specification: "a digit between 0 and 7 indicates that the
    /// ModR/M byte of the instruction uses only the r/m (register or memory)
    /// operand. The reg field contains the digit that provides an extension to
    /// the instruction's opcode."
    pub digit: u8,
    /// The number of bits used as an immediate operand to the instruction.
    ///
    /// From the specification: "a 1-byte (ib), 2-byte (iw), 4-byte (id) or
    /// 8-byte (io) immediate operand to the instruction that follows the
    /// opcode, ModR/M bytes or scale-indexing bytes. The opcode determines if
    /// the operand is a signed value. All words, doublewords, and quadwords are
    /// given with the low-order byte first."
    pub imm: Imm,
}

impl Vex {
    pub fn length(self, length: VexLength) -> Self {
        Self { length, ..self }
    }
    pub fn pp(self, pp: VexPP) -> Self {
        Self { pp, ..self }
    }
    pub fn mmmmm(self, mmmmm: VexMMMMM) -> Self {
        Self { mmmmm, ..self }
    }

    fn validate(&self, operands: &[Operand]) {
        /*
        assert!(self.digit < 8);
        assert!(!(self.r && self.digit > 0));
        assert!(!(self.r && self.imm != Imm::None));
        assert!(
            !(self.w && (self.prefixes.contains_66())),
            "though valid, if REX.W is set then the 66 prefix is ignored--avoid encoding this"
        );
        // assert!(self.prefixes.contains_66() && operands.iter().all(|&op| op == 16));

        if let Some(OperandKind::Imm(op)) = operands
            .iter()
            .map(|o| o.location.kind())
            .find(|k| matches!(k, OperandKind::Imm(_)))
        {
            assert_eq!(op.bits(), self.imm.bits());
        }
        */
    }
}

impl From<Vex> for Encoding {
    fn from(vex: Vex) -> Encoding {
        Encoding::Vex(vex)
    }
}

impl fmt::Display for Vex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VEX")?;
        /*    match self.prefixes {
            LegacyPrefixes::NoPrefix => {}
            LegacyPrefixes::_66 => write!(f, "0x66 + ")?,
            LegacyPrefixes::_F0 => write!(f, "0xF0 + ")?,
            LegacyPrefixes::_66F0 => write!(f, "0x66F0 + ")?,
            LegacyPrefixes::_F2 => write!(f, "0xF2 + ")?,
            LegacyPrefixes::_F3 => write!(f, "0xF3 + ")?,
            LegacyPrefixes::_66F3 => write!(f, "0x66F3 + ")?,
        }
        if self.w {
            write!(f, "REX.W + ")?;
        }
        */
        match self.length {
            VexLength::_128 => write!(f, ".128")?,
            VexLength::_256 => write!(f, ".256")?,
        }
        write!(f, " {:#04x}", self.opcode)?;

        /*
        if self.r {
            write!(f, " /r")?;
        }
        if self.digit > 0 {
            write!(f, " /{}", self.digit)?;
        }
        if self.imm != Imm::None {
            write!(f, " {}", self.imm)?;
        }*/

        Ok(())
    }
}

#[derive(PartialEq)]
pub enum VexLength {
    /// Operand size override -- here, denoting "16-bit operation".
    _128,
    /// The lock prefix.
    _256,
}

#[derive(PartialEq)]
pub enum VexPP {
    None,
    /// Operand size override -- here, denoting "16-bit operation".
    _66,
    /// The lock prefix.
    _F3,
    _F2,
}

#[derive(PartialEq)]
pub enum VexMMMMM {
    _OF,
    /// Operand size override -- here, denoting "16-bit operation".
    _OF3A,
    /// The lock prefix.
    _OF3B,
}
