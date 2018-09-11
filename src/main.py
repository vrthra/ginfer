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
        self.arg1 = self.update_args(len(arg), symbolic=True)
        self.initial_state = self.project.factory.entry_state(args=[self.exe, self.arg1])
        for i in range(len(arg)):
            self.initial_state.add_constraints(self.arg1a[i] == arg[i])
        # make sure that we have a terminator
        self.initial_state.add_constraints(self.arg1a[len(arg)] == 0)
        self.update_constraint_rep(self.initial_state)

    def run(self):
        state = self.initial_state
        while True:
            succ = state.step()
            if len(succ.successors) > 1:
                raise Exception('more successors %d' % len(succ.successors))
            if not succ.successors: return state
            state, = succ.successors

    def update_constraint_rep(self, state):
        """
        Used to check if a constraint has been updated
        """
        self.last_constraints = [claripy.simplify(c) for c in state.solver.constraints]

    def update_args(self, input_len, symbolic=True):
        """
        input contains the args
        """
        if not symbolic: return input
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
    prog.update_constraint_rep(res)
    for i in res.solver.constraints:
         print i
    print('done')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])