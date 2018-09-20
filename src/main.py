import sys
import os
import time
import angr
import random
import claripy
import tracer


class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        self.exe = exe
        self.project = angr.Project(exe, load_options={'auto_load_libs': False},
                main_opts={'custom_base_addr': 0x4000000000},
                )

    def set_input(self, arg):
        self.arg1 = self.make_symbolic_char_args(arg)
        self.initial_state = self.project.factory.entry_state(
                args=[self.exe, self.arg1],
                remove_options=angr.options.simplification
                )
        self.constrain_input_chars(self.initial_state, self.arg1a, arg)
        self.string_terminate(self.initial_state, self.arg1a, arg)
        self.simgr = self.project.factory.simgr(self.initial_state, mode='tracing')
        self.runner = tracer.QEMURunner(binary=self.exe, input='', project=self.project, argv=[self.exe, arg])
        self.simgr.use_technique(angr.exploration_techniques.Tracer(trace=self.runner.trace))
        self.seen = {}

    def int_to_str(self, val):
        return str(bytearray.fromhex('{:0100x}'.format(val)))

    # idea: we need only variables that relate to input bytes
    # wipe out any symbolics
    def transform(self, c):
        if c.op == 'BVV':
            val, bits = c.args
            for i in range(30):
                if val == i: return '\%d' % i
            return self.int_to_str(val)

        if c.op == 'BVS':
            return c.args[0]
        if c.op == '__eq__':
            return ([self.transform(a) for a in c.args], '__eq__')
        if c.op == 'SignExt':
            ([self.transform(a) for a in c.args[1:]], "OP:%s" % c.op)
        return ([self.transform(a) for a in c.args], "OP:%s" % c.op)

    def run(self):
        while len(self.simgr.active) >= 1:
            assert len(self.simgr.active) == 1
            for c in self.simgr.active[0].solver.constraints:
                if c.cache_key in self.seen:
                    continue
                self.seen[c.cache_key] = True
                print self.transform(c)
            self.simgr.step()
            print

    def string_terminate(self, state, symarg, inarg):
        self.initial_state.preconstrainer.preconstrain(0, symarg[len(inarg)])

    def constrain_input_chars(self, state, symarg, sarg):
        for i,a in enumerate(sarg):
            self.initial_state.preconstrainer.preconstrain(a, symarg[i])

    def make_symbolic_char_args(self, instr, symbolic=True):
        if not symbolic: return instr
        input_len = len(instr)
        largs = range(0, input_len+1)
        arg1k = ['%s_%d' % (Program.ARG_PREFIX, i) for i in largs]
        self.arg1k8 = {i:'%s_%d_%d_8' % (Program.ARG_PREFIX, i,i) for i in largs}
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

def main(exe, arg):
    prog = Program(exe)
    prog.set_input(arg)
    prog.run()
    for i in prog.simgr.deadended[0].solver.constraints:
        print(i.op, i.args)

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

