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

def to_str(root):
    if not isinstance(root, dict):
        return root
    myargs = []
    for i in root['args']:
        myargs.append(to_str(i))
    return root['fmt'] % tuple(myargs)

class PImpl:
    def __init__(self, obj):
        self.o = obj
        self.chars = {}
        for i in range(32): self.chars[i] = '%d' % i
        for i in range(32, 127): self.chars[i] = chr(i)

    def transform_symbolic(self, c, p=None):
        func = getattr(self, "x_" + c.op)
        if func:
            return func(c, p)
        else:
            print c.op
            assert False

    # idea: we need only variables that relate to input bytes
    # wipe out any symbolics
    def transform(self, c, parent=None):
        if is_concrete(c):
            assert c.op == 'BVV'
            val, bits = c.args
            return self.int_to_str(val)
        else:
            return self.transform_symbolic(c, parent)

    def int_to_str(self, val):
        if val < 31:
            return "%s" % self.chars[val]
        if val < 128:
            return "'%s'" % self.chars[val]
        d = sys.getsizeof(val)
        fmt = '{:0%dx}' % d
        return '%d' % d
        #return repr(str(bytearray.fromhex(fmt.format(val))).replace('\x00', ''))

    def x_LSHR(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'LShR'
        v.update({
            'fmt':"%s << %d",
            'args':[self.transform(c.args[0], v), c.args[1]],
            })
        return v
    def x_SignExt(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        # signext is a bit more complicated than zero ext for negative values
        assert c.op == 'SignExt'
        #assert c.args[0] == 32
        v.update({
            'fmt':"%s",
            'args':(self.transform(c.args[1], v),),
            })
        return v
    def x_ZeroExt(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'ZeroExt'
        #assert c.args[0] == 32
        # zero should only padd zeros to left. Hence it hould be a no-op
        v.update({
            'fmt':"%s",
            'args':(self.transform(c.args[1], v),),
            })
        return v
    def x_Extract(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'Extract'
        v.update({
            'fmt':"%s[%d:%d]",
            'args':(self.transform(c.args[2], v), c.args[0], c.args[1]),
            })
        return v
    def x_And(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'And'
        v.update({
            'fmt':"(%s && %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_Or(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'Or'
        v.update({
            'fmt':"(%s || %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___and__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__and__'
        v.update({
            'fmt':"(%s && %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___or__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__or__'
        v.update({
            'fmt':"(%s || %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___xor__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__xor__'
        v.update({
            'fmt':"(%s (+) %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___add__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__add__'
        v.update({
            'fmt':"(%s + %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___sub__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__sub__'
        v.update({
            'fmt':"(%s - %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___mul__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__mul__'
        v.update({
            'fmt':"(%s * %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___div__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__div__'
        v.update({
            'fmt':"(%s / %s)",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_Not(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'Not'
        v.update({
            'fmt':"not(%s)",
            'args':(self.transform(c.args[0], v),),
            })
        return v

    def x___lshift__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__lshift__'
        v.update({
            'fmt':"%s << %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___rshift__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__rshift__'
        v.update({
            'fmt':"%s >> %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v

    def x___lt__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__lt__'
        v.update({
            'fmt':"%s < %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___le__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__le__'
        v.update({
            'fmt':"%s <= %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___gt__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__gt__'
        v.update({
            'fmt':"%s > %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___ge__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__ge__'
        v.update({
            'fmt':"%s >= %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v

    def x_SLE(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'SLE'
        v.update({
            'fmt':"%s <= %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_SGE(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'SGE'
        v.update({
            'fmt':"%s >= %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_SGT(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'SGT'
        v.update({
            'fmt':"%s > %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_SLT(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'SLT'
        v.update({
            'fmt':"%s < %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_ULE(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'ULE'
        v.update({
            'fmt':"%s <= %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_UGE(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'UGE'
        v.update({
            'fmt':"%s >= %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_UGT(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'UGT'
        v.update({
            'fmt':"%s > %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x_ULT(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'ULT'
        v.update({
            'fmt':"%s < %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v

    def x_If(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'If'
        v.update({
            'fmt':"(If %s  then %s else %s)",
            'args':(self.transform(c.args[0], v),self.transform(c.args[1], v),self.transform(c.args[2], v)),
            })
        return v

    def x___ne__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__ne__'
        v.update({
            'fmt':"%s != %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v
    def x___eq__(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == '__eq__'
        v.update({
            'fmt':"%s == %s",
            'args':(self.transform(c.args[0], v), self.transform(c.args[1], v)),
            })
        return v

    def x_BVS(self, c, p=None):
        v = {'op':c.op, 'parent':p,'current':c}
        assert c.op == 'BVS'
        assert c.depth == 1
        if c.size() == 8:
            assert c.args[0].startswith(Program.ARG_PREFIX)
            self.o.vars.append({'i':self.o.arg1k8[c.args[0]], 'p':p, 'c':c})
            v.update({
                    'fmt':"i[%d]",
                    'args':(self.o.arg1k8[c.args[0]],),
                    })
            return v
        else:
            v.update({
                    'fmt':"<%s>",
                    'args':(c.args[0][0:-3] if c.args[0].endswith('_64') else c.args[0],),
                    })
            return v

class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        self.exe = exe
        self.project = angr.Project(exe, load_options={'auto_load_libs': False},
                main_opts={'custom_base_addr': 0x4000000000},
                )
        self.vars = []
        self.pimpl = PImpl(self)

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

    def get_var_val(self, c):
        val = c.args[0]
        var = c.args[1]
        if val.symbolic:
            assert var.concrete
            return val, var
        return var, val

    # idea: we need only variables that relate to input bytes
    # wipe out any symbolics
    def transform(self, c, parent=None):
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

    def extract(self, v):
        val = self.get_bool_op(v['p'])
        return to_str(val)


    def show_initial_constraints(self):
        assert len(self.simgr.active) == 1
        for c in self.simgr.active[0].solver.constraints:
            if c.cache_key in self.seen: continue
            self.seen[c.cache_key] = True
            do_print = True
            assert self.simgr.active[0].solver.eval(c)
            v = self.transform(c, {})
            if self.vars:
                print to_str(v), "\n", ">>\t", [self.extract(v) for v in self.vars]
            self.vars = []
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
                if self.vars:
                    print to_str(v), "\n", ">>\t", [self.extract(v) for v in self.vars]
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
        if prog.vars: print to_str(v), "\n", ">>\t", [prog.extract(v) for v in prog.vars]
        prog.vars = []

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

