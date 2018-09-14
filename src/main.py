import sys
import angr


class Program:
    ARG_PREFIX = 'sym_arg'
    def __init__(self, exe):
        self.exe = exe
        self.project = angr.Project(exe, load_options={'auto_load_libs': False})

    def set_input(self, arg):
        self.arg1 = arg
        self.initial_state = self.project.factory.entry_state(
                args=[self.exe, self.arg1], add_options=angr.options.unicorn)

    def run(self):
        state = self.initial_state
        while True:
            succ = state.step()
            if len(succ.successors) > 1:
                raise Exception('more successors %d' % len(succ.successors))
            if not succ.successors: return state
            state, = succ.successors

def main(exe, arg):
    prog = Program(exe)
    prog.set_input(arg)
    res = prog.run()
    print("constraints: %d" % len(res.solver.constraints))
    for c in res.solver.constraints:
        print(c)
    print('done')

if __name__ == '__main__':
    assert len(sys.argv) >= 3
    main(sys.argv[1], sys.argv[2])

