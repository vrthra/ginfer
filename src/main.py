import sys
import os
import time
import angr
import random
import claripy


class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        '''
        The program loads the binary for analysis. Using {auto_load_libs: false}
        tells angr to use an unconstrained value when a c-lib is called
        https://docs.angr.io/docs/loading.html#symbolic-function-summaries
        '''
        self.exe = exe
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})

    def set_input(self, arg):
        # generate arg1 from individual characters.
        self.arg1 = self.make_symbolic_char_args(arg)
        # state:
        #   mode=tracing enables unicorn
        #   simplification=false <-- should z3 simplifiers be invoked
        # s.options.add(angr.options..)
        # angr.options.CONCRETIZE
        # angr.options.SIMPLIFY_CONSTRAINTS
        # angr.options.SIMPLIFY_EXIT_GUARD
        # angr.options.SIMPLIFY_EXIT_STATE
        # angr.options.SIMPLIFY_EXIT_TARGET
        # angr.options.SIMPLIFY_EXPRS
        # angr.options.SIMPLIFY_MEMORY_READS
        # angr.options.SIMPLIFY_MEMORY_WRITES
        # angr.options.SIMPLIFY_REGISTER_READS
        # angr.options.SIMPLIFY_REGISTER_WRITES
        # angr.options.SIMPLIFY_RETS
        # angr.options.TRACK_SOLVER_VARIABLES
        # angr.options.UNICORN

        self.initial_state = self.project.factory.entry_state(
                args=[self.exe, self.arg1],
                # does not seem to startup the unicorn engine either
                add_options=angr.options.unicorn,
                # does not seem to affect the number of constraints created
                remove_options=angr.options.simplification
                )
        self.constrain_input_chars(self.initial_state, self.arg1a, arg)
        self.string_terminate(self.initial_state, self.arg1a, arg)

    def string_terminate(self, state, symarg, inarg):
        state.add_constraints(symarg[len(inarg)] == 0)

    def constrain_input_chars(self, state, symarg, sarg):
        constraints = []
        for i,a in enumerate(sarg):
            state.add_constraints(symarg[i] == a)

    def run(self):
        state = self.initial_state
        while True:
            succ = state.step()
            if len(succ.successors) > 1:
                raise Exception('more successors %d' % len(succ.successors))
            if not succ.successors: return state
            state, = succ.successors

    def make_symbolic_char_args(self, instr, symbolic=True):
        """
        input contains the args
        """
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
    res = prog.run()
    print("constraints: %d" % len(res.solver.constraints))
    print('done')

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

