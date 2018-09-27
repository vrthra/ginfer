import sys
class PImpl:
    def __init__(self, obj):
        self.o = obj
        self.chars = {}
        for i in range(32): self.chars[i] = '%d' % i
        for i in range(32, 127): self.chars[i] = chr(i)

    def is_concrete(self, val): return val.concrete
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
        if self.is_concrete(c):
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
            assert c.args[0].startswith(self.o.ARG_PREFIX)
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
