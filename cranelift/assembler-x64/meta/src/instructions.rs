//! Defines x64 instructions using the DSL.

mod add_v;
mod and;

use crate::dsl::Inst;

#[must_use]
pub fn list() -> Vec<Inst> {
    let mut instructions = and::list();
    instructions.extend(add_v::list());
    instructions
}
