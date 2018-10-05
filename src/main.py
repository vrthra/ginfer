import pudb
import string
breakpoint = pudb.set_trace
import logging
logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('tracer.qemu_runner').setLevel(logging.CRITICAL)

import sys
import z3
import os
import time
import angr
import random
import claripy
import tracer
import pimpl
from functools import reduce

def fprint(v=None):
    if v is not None:
        print(v)
        sys.stdout.flush()

def dassert(v=None): pass
    #assert v()

def log(v=None):
    pass
    #fprint(v)

def tracerun(v=None):
    sys.stdout.write(v)
    sys.stdout.flush()

def info(v=None): fprint()

def is_concrete(val): return val.concrete

def to_str(root):
    if not isinstance(root, dict): return root
    myargs = (to_str(i) for i in root['args'])
    return root['fmt'] % tuple(myargs)

class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        self.exe = exe
        self.project = angr.Project(exe,
                load_options={'auto_load_libs': False},
                main_opts={'base_addr': 0x4000000000},
                )
        self.vars = []
        self.pimpl = pimpl.PImpl(self)
        self.comparisons_with = {}
        self.is_running = False
        self.constraints = {'pre':[], 'running':[], 'post':[]}

    def set_input(self, arg):
        self.arg1 = self.make_symbolic_char_args(arg)
        self.initial_state = self.project.factory.entry_state(
                args=[self.exe, self.arg1],
                add_options=angr.options.unicorn,
                remove_options=angr.options.simplification)
        self.constrain_input_chars(self.initial_state, self.arg1a, arg)
        self.string_terminate(self.initial_state, self.arg1a, arg)
        self.simgr = self.project.factory.simgr(self.initial_state, mode='tracing')
        self.runner = tracer.QEMURunner(binary=self.exe, input=b'', project=self.project, argv=[self.exe, arg])
        self.simgr.use_technique(angr.exploration_techniques.Tracer(trace=self.runner.trace))
        self.seen = {}
        self.reset_comparisons()

    def reset_comparisons(self):
        self.comparisons_with = {i:[] for i in range(len(self.arg1a))}

    def get_var_val(self, c):
        val, var = c.args[0], c.args[1]
        if val.symbolic:
            assert var.concrete
            return val, var
        return var, val

    # idea: we need only variables that relate to input bytes
    # wipe out any symbolics
    def transform(self, c, parent=None):
        assert not self.is_running
        return self.pimpl.transform(c, parent)

    def get_bool_op(self, p):
        # things like And, Or etc require bool operands
        # hence they are above this level. These are
        # the operators that makr the transition from
        # arithmetic to bool so that we can evaluate their
        # arguments in pieces.
        if p['op'] in ['__eq__', '__ne__',
                       '__le__', '__lt__',
                       '__ge__', '__gt__']:
            return p
        return self.get_bool_op(p['parent'])

    def get_max_min(self, val, idx):
        solver = claripy.Solver()
        solver.add(val)
        sym = self.arg1a[idx]
        return (solver.max(sym), solver.min(sym))

    def extract(self, v):
        idx = v['i']
        val = self.get_bool_op(v['p'])['current']
        cmax,cmin = self.get_max_min(val, idx)
        #lhs = val.args[0]
        #rhs = val.args[1]
        return to_str(val), idx, int(cmax), int(cmin)


    def save_initial_constraints(self):
        assert len(self.simgr.active) == 1
        for c in self.simgr.active[0].solver.constraints:
            if c.cache_key in self.seen: continue
            self.seen[c.cache_key] = True
            self.constraints['pre'].append(c)

    def save_final_constraints(self):
        for c in self.simgr.deadended[0].solver.constraints:
            assert self.simgr.deadended[0].solver.eval(c)
            self.constraints['post'].append(c)

    def save_constraints(self):
        new_constraint = False
        for c in self.simgr.active[0].solver.constraints:
            if c.cache_key in self.seen: continue
            self.seen[c.cache_key] = True
            dassert(lambda: self.simgr.active[0].solver.eval(c))
            self.constraints['running'].append(c)
            new_constraint = True
        return new_constraint

    def transform_constraints(self, constraints):
        log("pre")
        for c in constraints:
            v = self.transform(c)
            if self.vars: info(to_str(v))
            for v in self.vars:
                s, idx, cmax, cmin = self.extract(v)
                self.comparisons_with[idx].append((cmin, cmax))
                log(">\t%s\t[%d]\t{%d,%d}" % (s, idx, cmin, cmax))
            self.vars = []

    def run(self):
        self.is_running = True
        while len(self.simgr.active) >= 1:
            assert len(self.simgr.active) == 1
            # assert self.simgr.active[0].satisfiable()
            if self.save_constraints(): tracerun('_')
            self.simgr.step()
        tracerun("\n")
        self.is_running = False

    def string_terminate(self, state, symarg, inarg):
        self.initial_state.preconstrainer.preconstrain(0, symarg[len(inarg)])

    def constrain_input_chars(self, state, symarg, sarg):
        for i,a in enumerate(sarg):
            self.initial_state.preconstrainer.preconstrain(a.encode('utf-8'), symarg[i])

    def make_symbolic_char_args(self, instr, symbolic=True):
        if not symbolic: return instr
        input_len = len(instr)
        largs = range(0, input_len+1)
        arg1k = ['%s_%d' % (Program.ARG_PREFIX, i) for i in largs]
        self.arg1k8 = {'%s_%d_%d_8' % (Program.ARG_PREFIX, i,i):i for i in largs}
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

Printable = sorted([i for i in string.printable])

def to_ascii(c):
    if c >= ord(Printable[0]) and c < ord(Printable[-1]):
        return chr(c)
    return c


def to_char(lst):
    return [to_ascii(x) if x == y else (x,y) for (x,y) in lst]

def main(exe, arg):
    prog = Program(exe)
    prog.set_input(arg)
    prog.save_initial_constraints()
    fprint('run[')
    prog.run()
    fprint('] return=%d' % prog.runner.returncode)
    prog.save_final_constraints()
    info()
    fprint('----')

    prog.reset_comparisons()
    prog.transform_constraints(prog.constraints['post'])
    for k in sorted(prog.comparisons_with.keys()): print(k, to_char(prog.comparisons_with[k]))
    fprint()

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

