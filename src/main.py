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

def is_concrete(val):
    return val.concrete


class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        self.exe = exe
        self.project = angr.Project(exe, load_options={'auto_load_libs': False},
                main_opts={'custom_base_addr': 0x4000000000},
                )
        self.vars = []

    def set_input(self, arg):
        self.arg1 = self.make_symbolic_char_args(arg)
        self.initial_state = self.project.factory.entry_state(
                args=[self.exe, self.arg1],
                add_options=angr.options.unicorn,
                remove_options=angr.options.simplification
                )
        self.constrain_input_chars(self.initial_state, self.arg1a, arg)
        self.string_terminate(self.initial_state, self.arg1a, arg)
        self.simgr = self.project.factory.simgr(self.initial_state, mode='tracing')
        self.runner = tracer.QEMURunner(binary=self.exe, input='', project=self.project, argv=[self.exe, arg])
        self.simgr.use_technique(angr.exploration_techniques.Tracer(trace=self.runner.trace))
        self.seen = {}
        self.chars = {}
        for i in range(32):
            self.chars[i] = '%d' % i
        for i in range(32, 127):
            self.chars[i] = chr(i)

    def int_to_str(self, val):
        if val < 31:
            return "%s" % self.chars[val]
        if val < 128:
            return "'%s'" % self.chars[val]
        d = sys.getsizeof(val)
        fmt = '{:0%dx}' % d
        return '%d' % d
        #return repr(str(bytearray.fromhex(fmt.format(val))).replace('\x00', ''))

    def get_var_val(self, c):
        val = c.args[0]
        var = c.args[1]
        if val.symbolic:
            assert var.concrete
            return val, var
        return var, val

    def transform_symbolic(self, c):
        if c.op == 'LShR': return "%s << %d" % (self.transform(c.args[0]), c.args[1])
        if c.op == 'SignExt': return self.transform(c.args[1])
        if c.op == 'ZeroExt': return self.transform(c.args[1])
        if c.op == 'Extract': return "%s[%d:%d]" % (self.transform(c.args[2]), c.args[0], c.args[1])
        if c.op == 'And': return "(%s && %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'Or': return "(%s && %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__and__': return "(%s && %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__or__': return "(%s || %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__xor__': return "(%s |x| %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__add__': return "(%s + %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__sub__': return "(%s - %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__mul__': return "(%s * %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__div__': return "(%s / %s)" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'Not': return "not(%s)" % self.transform(c.args[0])

        if c.op == '__lshift__': return "%s << %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__rshift__': return "%s >> %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))

        if c.op == '__lt__': return "%s < %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__le__': return "%s <= %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__gt__': return "%s > %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__ge__': return "%s >= %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))

        if c.op == 'SLE': return "%s <= %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'SGE': return "%s >= %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'SGT': return "%s > %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'SLT': return "%s < %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'ULE': return "%s <= %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'UGE': return "%s >= %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'UGT': return "%s > %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'ULT': return "%s < %s" %  (self.transform(c.args[0]), self.transform(c.args[1]))

        if c.op == 'If':
            return "(If(%s) then %s else %s)" % (self.transform(c.args[0]),self.transform(c.args[1]),self.transform(c.args[2]))

        if c.op == '__ne__': return "%s != %s" % (self.transform(c.args[0]),self.transform(c.args[1]))
        if c.op == '__eq__': return "%s == %s" % (self.transform(c.args[0]),self.transform(c.args[1]))

        if c.op == 'BVS':
            assert c.depth == 1
            if c.size() == 8:
                assert c.args[0].startswith(Program.ARG_PREFIX)
                self.vars.append(self.arg1k8[c.args[0]])
                return "i[%d]" % (self.arg1k8[c.args[0]])
            return "<%s>" % c.args[0][0:-3] if c.args[0].endswith('_64') else c.args[0]

        return ([self.transform(a) for a in c.args], "OP:%s" % c.op)

    # idea: we need only variables that relate to input bytes
    # wipe out any symbolics
    def transform(self, c):
        if is_concrete(c):
            assert c.op == 'BVV'
            val, bits = c.args
            return self.int_to_str(val)
        else:
            return self.transform_symbolic(c)

    def show_initial_constraints(self):
        assert len(self.simgr.active) == 1
        for c in self.simgr.active[0].solver.constraints:
            if c.cache_key in self.seen: continue
            self.seen[c.cache_key] = True
            do_print = True
            assert self.simgr.active[0].solver.eval(c)
            print self.transform(c)
        print

    def run(self):
        while len(self.simgr.active) >= 1:
            # sys.stdout.write('_')
            assert len(self.simgr.active) == 1
            do_print = False
            for c in self.simgr.active[0].solver.constraints:
                if c.cache_key in self.seen:
                    continue
                self.seen[c.cache_key] = True
                do_print = True
                assert self.simgr.active[0].solver.eval(c)

                v = self.transform(c)
                if self.vars: print v, "\n", ">>\t", self.vars
                self.vars = []

            self.simgr.step()
            #if do_print: print
            sys.stdout.flush()

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
        self.arg1k8 = {'%s_%d_%d_8' % (Program.ARG_PREFIX, i,i):i for i in largs}
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1h_ = {self.arg1h[k].args[0]:k for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

def main(exe, arg):
    prog = Program(exe)
    prog.set_input(arg)
    prog.show_initial_constraints()
    prog.run()
    print
    for c in prog.simgr.deadended[0].solver.constraints:
        assert prog.simgr.deadended[0].solver.eval(c)
        v = prog.transform(c)
        if prog.vars: print v, "\n", ">>\t", prog.vars
        prog.vars = []

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

