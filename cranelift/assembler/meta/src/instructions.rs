//! Defines x64 instructions using the DSL.

mod add_s;
mod and;
mod or;

use crate::dsl::Inst;

#[must_use]
pub fn list() -> Vec<Inst> {
    let mut instructions = and::list();
    instructions.extend(or::list());
    instructions.extend(add_s::list());
    instructions
}
