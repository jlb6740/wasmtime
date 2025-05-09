use crate::dsl::{align, fmt, inst, r, rex, rw, sxl, sxq};
use crate::dsl::{Feature::*, Inst, Location::*};

#[rustfmt::skip] // Keeps instructions on a single line.
pub fn list() -> Vec<Inst> {
    vec![
        // Vector instructions.
        inst("sqrtps", fmt("A", [rw(xmm), r(align(xmm_m128))]), rex([0x0F, 0x57]).r(), _64b | compat | sse),
        inst("sqrtpd", fmt("A", [rw(xmm), r(align(xmm_m128))]), rex([0x66, 0x0F, 0x57]).r(), _64b | compat | sse2),
        inst("sqrtss", fmt("A", [rw(xmm), r(align(xmm_m128))]), rex([0x66, 0x0F, 0xEF]).r(), _64b | compat | sse2),
        inst("sqrtsd", fmt("A", [rw(xmm), r(align(xmm_m128))]), rex([0x66, 0x0F, 0xEF]).r(), _64b | compat | sse2),
    ]
}
