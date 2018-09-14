import sys
import angr
import claripy

class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        self.exe = exe
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})

    def set_input(self, arg):
        # generate arg1 from individual characters.
        self.arg1 = self.make_symbolic_char_args(arg)

        # use LAZY_SOLVES to stay out of z3
        self.initial_state = self.project.factory.entry_state(
                args=[self.exe, self.arg1],
                add_options={angr.options.LAZY_SOLVES},
                remove_options=angr.options.simplification,
                )
        self.constrain_input_chars(self.initial_state, self.arg1a, arg)
        self.string_terminate(self.initial_state, self.arg1a, arg)

    def string_terminate(self, state, symarg, inarg):
        self.assignments[symarg[len(inarg)].cache_key] = claripy.BVV('\0')

    def constrain_input_chars(self, state, symarg, sarg):
        self.assignments = {}
        for i,a in enumerate(sarg):
            self.assignments[symarg[i].cache_key] = claripy.BVV(a)

    def run(self):
        state = self.initial_state
        passed = set()
        while True:
            succ = state.step()

            # do our own smart constraint solving since z3 is a blunt instrument
            successors = []
            for succ_state in succ.successors:
                for constraint in succ_state.solver.constraints:
                    # if we've already validated this don't bother
                    if constraint.cache_key in passed:
                        continue

                    # this might be the creation of a new symbol we need to register the value of
                    if constraint.op == '__eq__':
                        new_sym = None
                        new_val = None
                        new_val_conc = None
                        if constraint.args[0].op == 'BVS' and constraint.args[0].cache_key not in self.assignments:
                            new_sym, new_val = constraint.args
                        elif constraint.args[1].op == 'BVS' and constraint.args[1].cache_key not in self.assignments:
                            new_val, new_sym = constraint.args
                        if new_sym is not None:
                            if len(succ.successors) != 1:
                                raise Exception("I was not prepared for this")
                            new_val_conc = new_val.replace_dict(self.assignments)
                            if new_val_conc.op != 'BVV':
                                raise Exception("Couldn't come up with value for new symbol")
                            self.assignments[new_sym.cache_key] = new_val_conc
                            passed.add(constraint.cache_key)
                            continue

                    # try evaluating the constraint with our current assignments
                    better_constraint = constraint.replace_dict(self.assignments)
                    if better_constraint.is_false():
                        break
                    if not better_constraint.is_true():
                        raise Exception("Could not simplify constraint to true/false")
                    passed.add(constraint.cache_key)
                else:
                    successors.append(succ_state)

            if len(successors) > 1:
                raise Exception('more successors %d' % len(successors))
            if not successors: return state
            state, = successors

    def make_symbolic_char_args(self, instr, symbolic=True):
        if not symbolic: return instr
        input_len = len(instr)
        largs = range(0, input_len+1)
        arg1k = ['%s_%d' % (Program.ARG_PREFIX, i) for i in largs]
        self.arg1h = {k:claripy.BVS(k, 8) for k in arg1k}
        self.arg1a = [self.arg1h[k] for k in arg1k]
        return reduce(lambda x,y: x.concat(y), self.arg1a)

def main(exe, arg):
    prog = Program(exe)
    prog.set_input(arg)
    res = prog.run()
    print("constraints: %d" % len(res.solver.constraints))
    for i in res.solver.constraints:
        print(i)
    print('done')

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])
