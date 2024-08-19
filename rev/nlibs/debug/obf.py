from pycparser import parse_file
from pycparser.c_ast import *
from pycparser.c_generator import CGenerator
from pycparser.c_parser import CParser
from util import TransformVisitor
from ctypes import CDLL
import secrets
import os

libc = CDLL('libc.so.6')

ctx_varname = '_ctx'

class CDeclVisitor(NodeVisitor):
    def __init__(self):
        self.decls = []
        self.vars = []

    def insert_decl(self, node: Decl, name):
        if node in self.decls and name in self.vars:
            return
        assert node not in self.decls
        assert name not in self.vars
        self.decls.append(node)
        self.vars.append(name)

    def visit_Decl(self, node: Decl):
        if isinstance(node.type, TypeDecl): 
            self.insert_decl(node, node.name)
        elif isinstance(node.type, PtrDecl):
            self.insert_decl(node, node.name)
        elif isinstance(node.type, FuncDecl):
            if node.type.args is None:
                return
            params = node.type.args.params or []
            for param in params:
                self.insert_decl(param, param.name)
        elif isinstance(node.type, ArrayDecl):
            self.insert_decl(node, node.name)

        else:
            print(node)
            assert False
            

class CompoundVisitor(TransformVisitor):
    def __init__(self, cdecls):
        self.cdecls = cdecls

    def visit_Decl(self, node: Decl):
        if node.init == None:
            return node # FIXME: Need to strip all decls
        return Assignment('=', ID(node.name), node.init)

    def visit_Compound(self, node: Compound):
        block_items = []
        for block in node.block_items:
            if isinstance(block, Decl) and block.init == None:
                continue
            block_items.append(block)
        return Compound(block_items=block_items)

class InsertStruct(TransformVisitor):
    
    def __init__(self, struct_name, decls: list[Decl], vars):
        self.struct_name = ID(struct_name)
        self.decls = vars

    def visit_ID(self, node: ID):
        if node.name in self.decls:
            if isinstance(self.parent, StructRef) and self.parent.field == node: 
                '''
                If you have

                int i
                i++
                rc4->i
                rc4->a

                it gets transformed into 

                ctx->i++
                ctx->rc4->ctx->i
                ctx->rc4->a

                because conflict with the variable name i
                '''
                return
            return StructRef(self.struct_name, '->', node)

class CheckFlatten(NodeVisitor):
    def __init__(self):
        self.block_items = []
    
    def visit_Compound(self, node: Compound):
        assert self.block_items == []
        self.block_items = node.block_items

class ResolveLabels(TransformVisitor):
    def __init__(self, func_name):
        self.func_name = func_name
        self.goto_res = {}
    
    def visit_Label(self, node: Label):
        self.goto_res[node.name] = self.func_name
        return node.stmt

class UpdateGoto(TransformVisitor):
    def __init__(self, labels):
        self.labels = labels
        self.deps = []
    
    def visit_Goto(self, node: Goto):
        self.deps.append(self.labels[node.name])
        return Compound(block_items=[make_call(self.labels[node.name], ctx_varname), Return(expr=None)])

class GetFuncName(NodeVisitor):
    def __init__(self):
        self.func_name = None

    def visit_FuncDef(self, node):
        assert self.func_name is None, "This ast has more than one function definition"
        self.func_name = node.decl.name

class GetNames(NodeVisitor):
    def __init__(self, func_decls):
        self.func_decls = func_decls
        self.ids = []
    
    def visit_ID(self, node: ID):
        self.ids.append(node.name)

class GetReturnType(NodeVisitor):
    def __init__(self) -> None:
        self.type = None
    
    def visit_FuncDecl(self, node):
        assert self.type == None
        self.type = node.type

class UpdateReturnType(NodeVisitor):
    def __init__(self, type) -> None:
        self.type = type
    
    def visit_FuncDecl(self, node):
        if isinstance(self.type, PtrDecl):
            node.type.type = self.type
        else:
            node.type.type = self.type.type

class UpdateReturn(TransformVisitor):
    def __init__(self, ast, type):
        self.ast = ast
        self.has_return = False
        self.type = type

    def update(self, node):
        self.visit(node)
        if self.has_return == False:
            return
        res = UpdateReturnType(self.type)
        res.visit(node)

    def visit_Return(self, node: Return):
        self.has_return = True
        if node.expr is None:
            return Compound(block_items=[
                FuncCall(name=ID('free'), args=ExprList([ID(ctx_varname)])),
                Return(None)
            ])
        return Compound(block_items=[
            Decl(name='ret', quals=[], align=[], storage=[], funcspec=[], 
                 type=TypeDecl(declname='ret', quals=[], align=[], type=self.type),init=None, bitsize=None),
            Assignment('=', lvalue=ID('ret'), rvalue=node.expr),
            FuncCall(name=ID('free'), args=ExprList([ID(ctx_varname)])),
            Return(ID('ret'))
        ])

def get_func_name(ast):
    obj = GetFuncName()
    obj.visit(ast)
    return obj.func_name

def strip_decl(ast: Node):
    # Remove the c declarations from the ast and extract those values and return them.
    cdecl = CDeclVisitor()
    cdecl.visit(ast)
    comp = CompoundVisitor(cdecl.decls)
    comp.visit(ast)
    return cdecl.decls, cdecl.vars

def inject_struct(ast: Node, struct, decls, vars):
    # Replace occurances of variables from a=0 to ctx->a = 0
    ins = InsertStruct(ctx_varname, decls, vars)
    ins.visit(ast)
    ast.ext.insert(0, struct)

def to_struct(func_name, decls: list[Decl]):
    # Create a struct which contains all the variables for the "context" of the current function
    return Struct(func_name + '_ctx', decls)

_func_name_generator: any = None

def set_func_gen(generator):
    global _func_name_generator
    _func_name_generator = generator

def gen_func_name():
    return '_'.join(_func_name_generator.generate())

def inflate(ast: Node):
    # Prepare to seperate the code into individual lines. This will "inflate" it.
    orig_func_name = get_func_name(ast)
    
    chk = CheckFlatten()
    chk.visit(ast)
    ret = []
    func_names = [gen_func_name() for _ in range(len(chk.block_items))]
    # Split each line to it's own function
    func_deps = {}
    for key, block in enumerate(chk.block_items):
        blocks = [block]
        func_deps[func_names[key]] = []
        if key+1 < len(chk.block_items):
            # Goto the next line
            func_deps[func_names[key]].append(func_names[key + 1])
            # Call the next line
            blocks.append(make_call(func_names[key + 1], ctx_varname))
        ext = make_func(func_names[key], orig_func_name + '_ctx', blocks, extern=True)
        ret.append(FileAST(ext=[ext]))
    # Resolve the labels to the function_names
    goto_labels = {}
    for func, name in zip(ret, func_names):
        res = ResolveLabels(name)
        res.visit(func)
        goto_labels.update(res.goto_res)
    for func in ret:
        ret_type = GetReturnType()
        ret_type.visit(ast)
        res = UpdateReturn(ast, ret_type.type)
        res.update(func)
    for func, name in zip(ret, func_names):
        res = UpdateGoto(goto_labels)
        res.visit(func)
        func_deps[name].extend(res.deps)
    for ast, name in zip(ret, func_names):
        if name not in func_deps:
            continue
        for dep in func_deps[name]:
            ast.ext.insert(0, make_func_decl(dep, orig_func_name + '_ctx'))
    return ret, func_names

def make_func_decl(func_name, struct_name, block_items=[], ctx=ctx_varname):
    compound_node = Compound(block_items=block_items)
    type_decl_node = TypeDecl(declname=func_name, quals=[], align=[],
                                    type=IdentifierType(names=['void']))
    struct_type_node = PtrDecl(quals=[], type=TypeDecl(declname=ctx, quals=[], align=[], type=Struct(name=struct_name, decls=None)))

    struct_decl_node = Decl(name=ctx, quals=[], align=[], storage=[], funcspec=[],
                               type=struct_type_node, init=None,
                               bitsize=None)
    func_decl_node = FuncDecl(args=ParamList([struct_decl_node]),
                                    type=type_decl_node)
    func_def_node = Decl(name=func_name, quals=[], align=[], storage=[], funcspec=[],
                               type=func_decl_node, init=None,
                               bitsize=None)

    return func_def_node

def make_call(func_name, *args):
    # Helper function to call a function with args

    return FuncCall(ID(func_name), ExprList([ID(arg) for arg in args]))

def make_func(func_name, struct_name, block_items=[], ctx=ctx_varname, extern=False):
    # Helper function to make a function 
    compound_node = Compound(block_items=block_items)
    type_decl_node = TypeDecl(declname=func_name, quals=[], align=[],
                                    type=IdentifierType(names=['void']))
    struct_type_node = PtrDecl(quals=[], type=TypeDecl(declname=ctx, quals=[], align=[], type=Struct(name=struct_name, decls=None)))

    struct_decl_node = Decl(name=ctx, quals=[], align=[], storage=[], funcspec=[],
                               type=struct_type_node, init=None,
                               bitsize=None)
    func_decl_node = FuncDecl(args=ParamList([struct_decl_node]),
                                    type=type_decl_node)
    func_def_node = Decl(name=func_name, quals=[], align=[], storage=['extern'] if extern else [], funcspec=[],
                               type=func_decl_node, init=None,
                               bitsize=None)
    main_func_node = FuncDef(decl=func_def_node, param_decls=None,
                                   body=compound_node)

    return main_func_node

def get_func_decl(ast):
    parser = CParser()
    ree = parser.parse('''
void foo(int a, void* b);
                 ''')
    decl = Decl(name='foo', quals=[], align=[], storage=[], funcspec=[], type=ast.ext[0].decl.type, init=None, bitsize=None)
    return decl

def insert_decl(ast, decls):
    getname = GetNames(decls)
    getname.visit(ast)
    for id in getname.ids:
        if id not in decls:
            continue
        ast.ext.insert(0, decls[id])

def abstract_call(ast, next_func):
    # TODO modify all returns to add a free right before it returns
    orig_func_name = get_func_name(ast)
    parser = CParser()
    load_args = []
    if ast.ext[1].decl.type.args:
        for param in ast.ext[1].decl.type.args.params:
            param_name = param.name
            load_args.append(f'{ctx_varname}->{param_name} = {param_name};')
    tmp = parser.parse(f'''
extern void tmp(){{
    struct {orig_func_name}_ctx* {ctx_varname} = malloc(sizeof(struct {orig_func_name}_ctx));
    {'\n'.join(load_args)}
}}''')
    body = Compound(
        block_items=[
            *tmp.ext[0].body.block_items,
            make_call(next_func, ctx_varname)
        ]
    )
    orig_decl: Decl = ast.ext[1].decl
    
    if orig_func_name == 'main':
        decl = orig_decl
    else:
        decl = Decl(name=orig_decl.name, quals=orig_decl.quals, align=orig_decl.align, storage=list(set(orig_decl.storage).union(set(["extern"]))),
                    funcspec=orig_decl.funcspec, type=FuncDecl(
                        args=orig_decl.type.args,
                        type=TypeDecl(declname=orig_func_name, quals=[], align=[],
                                    type=IdentifierType(names=['void']))
                    ), init=orig_decl.init, bitsize=orig_decl.bitsize)
    func = FuncDef(decl=decl, param_decls=ast.ext[1].param_decls, body=body)
    # print(func)
    ast = FileAST(ext=[make_func_decl(next_func, orig_func_name + '_ctx'), func])
    return ast, orig_func_name

def dump(ast: Node):
    generator = CGenerator()
    return generator.visit(ast)

dest_dir = 'build'

def generate_source(asts, func_names, struct, headers, directory):
    generator = CGenerator()

    file_names = [secrets.token_hex(6) for _ in range(len(func_names))]
    
    for i in range(len(func_names)):
        if func_names[i] == 'main':
            file_names[i] = 'main'

    for ast, next_ast, func_name, next_func, file_name in zip(asts, asts[1:]+[None], func_names, func_names[1:] + [None], file_names):
        f = open(f"build/{directory}/{file_name}.c", 'w')
        f.write(headers)
        f.write(struct+';\n')
        f.write(generator.visit(ast))
        f.close()

    return file_names

def generate_makefile(file_names, directory, dst_dir):
    make = open(f'build/{directory}/Makefile', 'w')
    make.write('''CFLAGS := -Wall -fPIC

all: clean build

clean: 
\trm -f *.so *.o main

build:
''')
    if 'main' in file_names:
        file_names.remove('main')

    file_names_r = file_names[::-1]
    for file_name, prev_name in zip(file_names_r, [None]+file_names_r[:-1]):
        make.write(f'\tgcc $(CFLAGS) -c {file_name}.c -o {file_name}.o\n')
        if prev_name:
            make.write(f'\tgcc -L. -l{prev_name} -shared {file_name}.o -o lib{file_name}.so\n')
        else:
            make.write(f'\tgcc -shared {file_name}.o -o lib{file_name}.so\n')
    libs = ' '.join(['-l'+file for file in file_names])
    make.write(f'\tgcc -L. -Wl,-rpath,\'.\' {libs} main.c -o main\n')
    make.write(f'\tcp *.so main {dst_dir}/\n')
    make.write(f'\trm *.so main\n')
    make.close()

def obfuscate(directory, generator, dst_dir):
    set_func_gen(generator)
    ast: Node = parse_file(f'srcs/{directory}/main.c99')
    generator = CGenerator()

    package = []

    func_decls = {

    }


    for func in ast.ext:
        func_ast = FileAST(ext=[func])
        func_decl = get_func_decl(func_ast)
        decls, vars = strip_decl(func_ast)
        func_name = get_func_name(func_ast)
        func_decls[func_name] = func_decl
        struct = to_struct(func_name, decls)
        inject_struct(func_ast, struct, decls, vars)
        # print(dump(func_ast))
        asts, func_names = inflate(func_ast)
        func, name = abstract_call(func_ast, func_names[0])
        asts.append(func)
        func_names.append(name)
        package.append((asts, func_names, dump(struct)))

    for asts, func_names, struct in package:
        for ast in asts:
            insert_decl(ast, func_decls)

    func_names = set(func_decls.keys())

    # for ast in asts:
    #     print(generator.visit(ast))

    f = open(f'srcs/{directory}/main.c','r')
    headers = f.read().split('/* END INCLUDE SECTION */')[0]
    f.close()


    os.system(f"rm -f build/{directory}/*")


    file_names = []

    for asts, func_names, struct in package:
        file_names.extend(generate_source(asts, func_names, struct, headers, directory))

    generate_makefile(file_names, directory, dst_dir)
