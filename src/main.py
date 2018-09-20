import sys
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
        self.chars = {}
        for i in range(32):
            self.chars[i] = '\\%d' % i
        for i in range(32, 127):
            self.chars[i] = chr(i)

    def int_to_str(self, val):
        if val < 128:
            return "'%s'" % self.chars[val]
        d = sys.getsizeof(val)
        fmt = '{:0%dx}' % d
        return str(bytearray.fromhex(fmt.format(val))).replace('\x00', '')

    def get_var_val(self, c):
        val = c.args[0]
        var = c.args[1]
        if val.symbolic:
            assert var.concrete
            return val, var
        return var, val

    def transform_symbolic(self, c):
        #if not c.is_true() and not c.is_false():
        #    return '<symbolic>'
        if c.op == 'LShR': return "%s << %d" % self.transform(c.args[0], c.args[1])
        if c.op == 'SignExt': return self.transform(c.args[1])
        if c.op == 'ZeroExt': return self.transform(c.args[1])
        if c.op == 'Extract': return "%s[%d:%d]" % (self.transform(c.args[2]), c.args[0], c.args[1])
        if c.op == '__and__': return "%s && %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__or__': return "%s || %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__xor__': return "%s xor %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__add__': return "%s + %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == '__sub__': return "%s - %s" % (self.transform(c.args[0]), self.transform(c.args[1]))
        if c.op == 'Not': return "not(%s)" % self.transform(c.args[0])
        if c.op == 'If': return "(If(%s) then %s else %s)" % (self.transform(c.args[0]),self.transform(c.args[1]),self.transform(c.args[2]))

        if c.op == 'SLE': return "%s <= %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'SGE': return "%s >= %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'SGT': return "%s > %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'SLT': return "%s < %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'ULE': return "%s <= %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'UGE': return "%s >= %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'UGT': return "%s > %s" % (self.transform(c.args[0]), self.transform(c.args[0]))
        if c.op == 'ULT': return "%s < %s" % (self.transform(c.args[0]), self.transform(c.args[0]))


        if c.op == '__ne__':
            #if c.depth == 2:
            #    var, val = self.get_var_val(c)
            #    assert val.size() == 8
            #    return "i[%d] != %s" % (self.arg1k8[var.args[0]], "'%s'" % chr(val.args[0]) if val.args[0] != 0 else '0' )
            #else:
                return "%s != %s" % (self.transform(c.args[0]),self.transform(c.args[1]))

        if c.op == '__eq__':
            #if c.depth == 2:
            #    var, val = self.get_var_val(c)
            #    assert val.size() == 8
            #    return "i[%d] == %s" % (self.arg1k8[var.args[0]], "'%s'" % chr(val.args[0]) if val.args[0] != 0 else '0' )
            #else:
                return "%s == %s" % (self.transform(c.args[0]),self.transform(c.args[1]))

        if c.op == 'BVS':
            assert c.depth == 1
            if c.size() == 8:
                assert c.args[0].startswith(Program.ARG_PREFIX)
                return "i[%d]" % (self.arg1k8[c.args[0]])
            # check c.size() == 8 for finding if it represents a char
            # check the arg prefix
            # a leaf node
            return "<%s>" % c.args[0]


        #if c.op == '__eq__':
        #    return ([self.transform(a) for a in c.args], '__eq__')
        #if c.op == 'SignExt':
        #    ([self.transform(a) for a in c.args[1:]], "OP:%s" % c.op)
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

    def run(self):
        while len(self.simgr.active) >= 1:
            assert len(self.simgr.active) == 1
            do_print = False
            for c in self.simgr.active[0].solver.constraints:
                if c.cache_key in self.seen:
                    continue
                self.seen[c.cache_key] = True
                do_print = True
                print self.initial_state.solver.eval(c), "\t", self.transform(c)
            self.simgr.step()
            if do_print:
                print
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
    prog.run()
    #print "------"
    #for i in prog.simgr.deadended[0].solver.constraints:
    #    print(i.op, i.args)

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

