#!/usr/bin/env python

import angr, claripy
import IPython
import logging, sys
from angr.block import CapstoneInsn

l = logging.getLogger("angr")

# silence some annoying logs
l.setLevel("WARNING")

def getFuncAddress(cfg, funcName, plt=None ):
    found = [
        addr for addr,func in cfg.kb.functions.items()
        if funcName == func.name and (plt is None or func.is_plt == plt)
    ]
    if len( found ) > 0:
        l.info("Found "+funcName+"'s address at "+hex(found[0])+"!")
        return found[0]
    else:
        raise Exception("No address found for function : "+funcName)

def getRetAddr(proj, fn):
    # let's disasm with capstone to search targets
    insn_bytes = proj.loader.memory.load(fn, 1000)
    for cs_insn in proj.arch.capstone.disasm(insn_bytes, fn):
        ins = CapstoneInsn(cs_insn)
        if ins.mnemonic == "ret":
            l.info(f"Found lfsr's return address at 0x{ins.address:x}!")
            return ins.address
    raise ValueError("failed to find ret op in {fn}")

def main(binary):
    proj = angr.project.Project(binary, use_sim_procedures=False, load_options={'auto_load_libs':False})

    cfg = proj.analyses.CFG(fail_fast=True)
    l.info("created CFG")

    tgtfn = getFuncAddress(cfg, 'init_state')
    final_addr = getRetAddr(proj, tgtfn)
    key = claripy.BVS("key",16*8)
    lfsr_state = claripy.BVS("lfsr_state",16*8)
    state = proj.factory.blank_state(addr=tgtfn)
    state.options |= { angr.sim_options.LAZY_SOLVES,
                       angr.sim_options.SIMPLIFY_CONSTRAINTS,
                       angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER,
                       angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                       angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS}

    state.regs.rax = 0
    state.regs.rbx = 0
    state.regs.rbp = 0
    state.regs.r12 = 0
    state.regs.r13 = 0
    state.regs.r14 = 0
    state.regs.r15 = 0
    state.regs.ftop = 0

    # key is symbolic
    for byte in key.chop(8):
        state.add_constraints(byte < 16)
        state.add_constraints(byte >= 0)

    state.regs.rdi = state.solver.BVV(0xd000000, 128)
    state.memory.store(0xd000000,key)

    state.regs.rsi = state.solver.BVV(0xd000010, 128)
    state.memory.store(0xd000010,lfsr_state)

    state.solver.simplify()

    simgr = proj.factory.simulation_manager(state, veritesting=True)
    simgr.explore(find=final_addr)

    s= simgr.found[0].copy()

    s.solver.simplify(s.memory.load(0xd000010, 16))

    print("init_lfsr -> lfsr_state:", s.memory.load(0xd000010, 16))

    tgtfn = getFuncAddress(cfg, 'lfsr')
    final_addr = getRetAddr(proj, tgtfn)
    state = proj.factory.blank_state(addr=tgtfn)

    # input_key is symbolic, and 1st and only param to the tgt fn
    lfsr_state = claripy.BVS("lfsr_state",16*8)
    lfsr_newstate = claripy.BVS("lfsr_newstate",16*8)

    state.regs.rdi = state.solver.BVV(0xd000000, 128)
    state.memory.store(0xd000000,lfsr_state)

    state.regs.rsi = state.solver.BVV(0xd000010, 128)
    state.memory.store(0xd000010,lfsr_newstate)

    state.options |= { angr.sim_options.LAZY_SOLVES,
                       angr.sim_options.SIMPLIFY_CONSTRAINTS,
                       angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER,
                       angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                       angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS}

    state.regs.rax = 0
    state.regs.rbx = 0
    state.regs.rbp = 0
    state.regs.r12 = 0
    state.regs.r13 = 0
    state.regs.r14 = 0
    state.regs.r15 = 0
    state.regs.ftop = 0

    simgr = proj.factory.simulation_manager(state, veritesting=True)
    simgr.explore(find=final_addr)

    s= simgr.found[0].copy()

    s.solver.simplify(s.memory.load(0xd000010, 16))

    print("lfsr -> next state:", s.memory.load(0xd000010, 16))

    tgtfn = getFuncAddress(cfg, 'extract_lfsr')
    final_addr = getRetAddr(proj, tgtfn)
    state = proj.factory.blank_state(addr=tgtfn)

    # input_key is symbolic, and 1st and only param to the tgt fn
    lfsr_state = claripy.BVS("lfsr_state",16*8)

    state.regs.rdi = state.solver.BVV(0xd000000, 128)
    state.memory.store(0xd000000,lfsr_state)

    state.options |= { angr.sim_options.LAZY_SOLVES,
                       angr.sim_options.SIMPLIFY_CONSTRAINTS,
                       angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER,
                       angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                       angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    state.options -= {angr.sim_options.COMPOSITE_SOLVER}

    state.regs.rax = 0
    state.regs.rbx = 0
    state.regs.rbp = 0
    state.regs.r12 = 0
    state.regs.r13 = 0
    state.regs.r14 = 0
    state.regs.r15 = 0
    state.regs.ftop = 0

    simgr = proj.factory.simulation_manager(state, veritesting=True)
    simgr.explore(find=final_addr)

    s= simgr.found[0].copy()

    s.solver.simplify(s.regs.rax)

    print("lfsr_out:", s.regs.rax)

    #IPython.embed()

if __name__ == '__main__':
    main("./angr_tgt")

