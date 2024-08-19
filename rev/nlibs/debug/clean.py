from pycparser import parse_file, c_generator
from pycparser.c_ast import *
from util import TransformVisitor
import sys
import os


def get_token(name=''):
    return name+'_'+os.urandom(4).hex()

class NestedFuncCall:
    def visit(self, node, infunc=False):
        for c in node:
            if isinstance(c, FuncCall):
                assert infunc == False, "Nested Function Calls are not allowed"
                self.visit(c, infunc=True)
            else:
                self.visit(c, infunc=infunc)

class Unroll(TransformVisitor):
    def expand(self, val):
        if isinstance(val, Compound):
            return val.block_items
        return [val]

    def expand_decl(self, val):
        if isinstance(val, DeclList):
            return val.decls
        return [val]

    def visit_For(self, node: For):
        cond = get_token('COND')
        loop = get_token('LOOP')
        return Compound(block_items=[
            *self.expand_decl(node.init),
            # goto REE
            Goto(name=cond),
            Label(name=loop, stmt=None),
            # label ROO:
            *node.stmt.block_items,
            node.next,
            # label REE
            Label(name=cond, stmt=None),
            If(cond=node.cond, iftrue=Goto(name=loop), iffalse=None)
            # if(cond) goto ROO
        ])
        return node

    def visit_If(self, node: If):
        true = get_token("TRUE")
        false = get_token("FALSE")
        end = get_token("END")
        assert not isinstance(node.iffalse, If)
        if isinstance(node.iffalse, Compound):
            return Compound(block_items=[
                If(cond=node.cond, iftrue=Goto(true), iffalse=Goto(false)),
                Label(name=true, stmt=None),
                *self.expand(node.iftrue),
                Goto(end),
                Label(name=false, stmt=None),
                *self.expand(node.iffalse),
                Label(name=end, stmt=None)
            ])
        assert node.iffalse is None
        return Compound(block_items=[
            If(cond=node.cond, iftrue=Goto(true), iffalse=Goto(false)),
            Label(name=true, stmt=None),
            *self.expand(node.iftrue),
            Label(name=false, stmt=None)
        ])

    def visit_While(self, node: While):
        return node

    def visit_DoWhile(self, node: DoWhile):
        return node


class Flatter(TransformVisitor):
    def visit_Compound(self, node: Compound):
        block_items = []
        for i in range(len(node.block_items)):
            if isinstance(node.block_items[i], Compound):
                block_items.extend(node.block_items[i].block_items)
            else:
                block_items.append(node.block_items[i])
        return Compound(block_items=block_items)

class StripDecls(TransformVisitor):
    def __init__(self):
        self.decls = []

    def visit_Decl(self, node: Decl):
        if node.init:
            if node.name not in [decl.name for decl in self.decls]:
                self.decls.append(node)
            init = node.init
            node.init = None
            return Assignment(op='=', lvalue=ID(node.name), rvalue=init)
        

def C99ify(ast):
    for func in ast.ext:
        strip = StripDecls()
        strip.visit(func.body)
        func.body.block_items = strip.decls + func.body.block_items

def clean(directory):
    f = open(f'srcs/{directory}/main.c99', 'rb')
    data = f.read()
    f.close()
    data = data[data.index(b'/* END INCLUDE SECTION */'):]
    data = b'\n'.join([line for line in data.split(b'\n') if not line.startswith(b'# ') and not line.startswith(b'/')])
    f = open(f'srcs/{directory}/main.c99', 'wb')
    f.write(data)
    f.close()

    ast = parse_file(f'srcs/{directory}/main.c99')
    NestedFuncCall().visit(ast)
    res = Unroll()
    flatter = Flatter()
    res.visit(ast)
    flatter.visit(ast)
    C99ify(ast)
    generator = c_generator.CGenerator()
    f = open(f'srcs/{directory}/main.c99', 'w')
    f.write(generator.visit(ast).replace('\n\n','\n'))
    f.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"python {sys.argv[0]} [directory]")
        exit(0)

    clean(sys.argv[1])

