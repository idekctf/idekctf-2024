#!/usr/local/bin/python3

import re
import os
import sys

class Directory:
    def __init__(self, name, parent=None):
        self.name = name
        self.children = dict()
        self.parent = parent
        self.is_root = False
        if not self.parent:
            self.parent = self

class RegularFile:
    def __init__(self, name, content=""):
        self.name = name
        self.write(content)
    
    def read(self):
        return self.content
    
    def write(self, content):
        self.content = content
    
    def append(self, content):
        self.content += content

class Symlink:
    def __init__(self, name, target):
        self.name = name
        self.target = target

class Shell:
    def __init__(self):
        self.root = Directory('/')
        self.root.is_root = True
        self.cwd = self.root
        self.displaycwd = []
    
    def __navigate(self, path, striplast=True, cur=None):
        displaycwd = self.displaycwd.copy()
        if not cur:
            if path[0] == '/':
                cur = self.root
                path = path[1:]
                displaycwd = []
            else:
                cur = self.cwd
        if striplast:
            path = path.split('/')[:-1]
        else:
            path = path.split('/')
        for token in path:
            if token == '.' or token == '':
                continue
            if token == '..':
                if cur == cur.parent and not cur.is_root:
                    sys.stderr.write("oooops: filesystem corruption\n")
                    sys.exit(1)
                cur = cur.parent
                if len(displaycwd) > 0:
                    displaycwd.pop()
                continue
            if token not in cur.children:
                return None, "No such file or directory"
            if type(cur.children[token]) == RegularFile:
                return None, "Not a directory"
            elif type(cur.children[token]) == Symlink:
                cur, _ = self.__navigate(cur.children[token].target, False, cur)
                if not cur:
                    return None, "No such file or directory"
            else:
                cur = cur.children[token]
            displaycwd.append(token)
        return cur, displaycwd

    def mkdir(self, name):
        cur, _ = self.__navigate(name.rstrip("/"))
        if not cur:
            return 1, "", "cannot create directory '{}': {}".format(name, _)
        token = name.rstrip("/").split('/')[-1]
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', token):
            return 1, "", "cannot create directory '{}': Invalid directory name".format(name)
        if token in cur.children:
            return 1, "", "cannot create directory '{}': File exists".format(name)
        cur.children[token] = Directory(token, cur)
        return 0, "", ""

    def cd(self, name="/"):
        if name.rstrip("/") == "":
            self.cwd = self.root
            self.displaycwd = []
            return 0, "", ""
        cur, displaycwd = self.__navigate(name.rstrip("/"), False)
        if not cur:
            return 1, "", "cd: {}: {}".format(name, displaycwd)
        self.cwd = cur
        self.displaycwd = displaycwd
        if len(self.displaycwd) > 0 and self.displaycwd[-1] not in self.cwd.parent.children:
            self.displaycwd = [self.cwd.name]
            cur = self.cwd.parent
            while not cur.is_root:
                self.displaycwd.insert(0, cur.name)
                cur = cur.parent
        return 0, "", ""

    def ls(self):
        return 0, "\n".join(self.cwd.children.keys()), ""
    
    def echo(self, *args):
        return 0, " ".join(args), ""

    def touch(self, name):
        cur, _ = self.__navigate(name.rstrip("/"))
        if not cur:
            return 1, "", "cannot touch '{}': {}".format(name, _)
        token = name.rstrip("/").split('/')[-1]
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', token) or token in ['.', '..']:
            return 1, "", "cannot touch '{}': Invalid file name".format(name)
        if token not in cur.children:
            cur.children[token] = RegularFile(token)
        return 0, "", ""

    def cat(self, name):
        cur, _ = self.__navigate(name.rstrip("/"))
        if not cur:
            return 1, "", "cat: {}: {}".format(name, _)
        token = name.rstrip("/").split('/')[-1]
        if token not in cur.children:
            return 1, "", "cat: {}: No such file or directory".format(name)
        return 0, cur.children[token].read(), ""

    def ln(self, target, name):
        cur, _ = self.__navigate(name.rstrip("/"))
        if not cur:
            return 1, "", "ln: {}: {}".format(name, _)
        token = name.rstrip("/").split('/')[-1]
        if token in cur.children:
            return 1, "", "ln: {}: File exists".format(name)
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', name):
            return 1, "", "ln: {}: Invalid file name".format(name)
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', target):
            return 1, "", "ln: {}: Invalid target name".format(target)
        cur.children[token] = Symlink(name, target)
        return 0, "", ""

    def rm(self, name):
        if name.rstrip("/") == "":
            return 1, "", "rm: really?"
        cur, _ = self.__navigate(name.rstrip("/"))
        if not cur:
            return 1, "", "rm: {}: {}".format(name, _)
        token = name.rstrip("/").split('/')[-1]
        if token not in cur.children:
            return 1, "", "rm: {}: No such file or directory".format(name)
        if type(cur.children[token]) == Directory:
            if len(cur.children[token].children) > 0:
                return 1, "", "rm: {}: Directory not empty".format(name)
            cur.children[token].parent = cur.children[token]
        del cur.children[token]
        return 0, "", ""
    
    def create_flag(self):
        if "flag.txt" not in self.root.children:
            self.root.children["flag.txt"] = RegularFile("flag.txt", os.getenv("FLAG") or "idek{fake_flag}")
            return 0, "", ""
        return 1, "", "flag.txt already exists"
    
    def _run(self):
        funcs = [func for func in dir(Shell) if callable(getattr(Shell, func))]
        funcs = [func for func in funcs if not func.startswith("_")]

        last_command = ""
        last_ret = 0

        while True:
            cmd = input("user@memoryFS:/{}$ ".format("/".join(self.displaycwd)))
            if cmd == "exit":
                break
            tokens = cmd.split()
            if len(tokens) == 0:
                continue
            if tokens[0] in ["cat", "cd"] and "flag.txt" in cmd:
                sys.stderr.write("nein\n")
                continue
            if tokens[0] not in funcs:
                sys.stderr.write("command not found\n")
                continue
            for i in range(1, len(tokens)):
                if tokens[i] == "$_":
                    tokens[i] = last_command
                elif tokens[i] == "$0":
                    tokens[i] = tokens[0]
                elif tokens[i] == "$?":
                    tokens[i] = str(last_ret)
                elif tokens[i] == "$#":
                    tokens[i] = str(len(tokens) - 1)
                elif tokens[i] == "$PWD":
                    tokens[i] = "/" + "/".join(self.displaycwd)
            ret, stdout, stderr = getattr(self, tokens[0])(*tokens[1:])
            last_command = tokens[0]
            last_ret = ret
            if stdout:
                sys.stdout.write(stdout + "\n")
            if stderr:
                sys.stderr.write(stderr + "\n")


if __name__ == "__main__":
    shell = Shell()
    shell._run()
