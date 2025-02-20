use crate::dsl::{fmt, inst, r, vex, w, Feature::*, Inst, Location::*, VexLength::*, VexMMMMM::*, VexPP::*};

pub fn list() -> Vec<Inst> {
    vec![
        //inst("addss", fmt("I", [rw(al), r(imm8)]), rex(0x24).ib(), None),
        //inst("addsd", fmt("I", [rw(ax), r(imm16)]), rex(0x25).prefix(_66).iw(), None),
        //inst("addps", fmt("I", [rw(al), r(imm8)]), rex(0x24).ib(), None),
        //inst("addpd", fmt("I", [rw(ax), r(imm16)]), rex(0x25).prefix(_66).iw(), None),
        //inst("vaddss", fmt("I", [rw(ax), r(imm16)]), rex(0x25).prefix(_66).iw(), None),
        //inst("vaddsd", fmt("I", [rw(ax), r(imm16)]), rex(0x25).prefix(_66).iw(), None),
        //inst("vaddps", fmt("I", [rw(ax), r(imm16)]), rex(0x25).prefix(_66).iw(), None),
        inst(
            "vaddpd",
            fmt("B", [w(xmm1), r(xmm2), r(xmm3m128)]),
            vex(0x58).length(_128).pp(_66).mmmmm(_OF),
            _64b | compat,
        ),
    ]
}
