builtins_whitelist = set(
    (
        "RuntimeError",
        "Exception",
        "KeyboardInterrupt",
        "False",
        "None",
        "True",
        "bytearray",
        "bytes",
        "dict",
        "float",
        "int",
        "list",
        "object",
        "set",
        "str",
        "tuple",
        "abs",
        "all",
        "any",
        "apply",
        "bin",
        "bool",
        "buffer",
        "callable",
        "chr",
        "classmethod",
        "cmp",
        "coerce",
        "compile",
        "delattr",
        "dir",
        "divmod",
        "enumerate",
        "filter",
        "format",
        "hasattr",
        "hash",
        "hex",
        "id",
        "input",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "map",
        "max",
        "min",
        "next",
        "oct",
        "open",
        "ord",
        "pow",
        "print",
        "property",
        "range",
        "reduce",
        "repr",
        "reversed",
        "round",
        "setattr",
        "slice",
        "sorted",
        "staticmethod",
        "sum",
        "super",
        "unichr",
        "xrange",
        "zip",
        "len",
        "sort",
    )
)


class ReadOnlyBuiltins(dict):
    def clear(self):
        raise RuntimeError("Nein")

    def __delitem__(self, key):
        raise RuntimeError("Nein")

    def pop(self, key, default=None):
        raise RuntimeError("Nein")

    def popitem(self):
        raise RuntimeError("Nein")

    def setdefault(self, key, value):
        raise RuntimeError("Nein")

    def __setitem__(self, key, value):
        raise RuntimeError("Nein")

    def update(self, dict, **kw):
        raise RuntimeError("Nein")


def _safe_open(open, submission_id):
    def safe_open(file, mode="r"):
        if mode != "r":
            raise RuntimeError("Nein")
        file = str(file)
        if file.endswith(submission_id + ".expected"):
            raise RuntimeError("Nein")
        return open(file, "r")

    return safe_open


class Sandbox(object):
    def __init__(self, submission_id):
        import sys
        from ctypes import pythonapi, POINTER, py_object

        _get_dict = pythonapi._PyObject_GetDictPtr
        _get_dict.restype = POINTER(py_object)
        _get_dict.argtypes = [py_object]
        del pythonapi, POINTER, py_object

        def dictionary_of(ob):
            dptr = _get_dict(ob)
            return dptr.contents.value
        type_dict = dictionary_of(type)
        del type_dict["__bases__"]
        del type_dict["__subclasses__"]
        original_builtins = sys.modules["__main__"].__dict__["__builtins__"].__dict__
        original_builtins["open"] = _safe_open(open, submission_id)
        for builtin in list(original_builtins):
            if builtin not in builtins_whitelist:
                del sys.modules["__main__"].__dict__["__builtins__"].__dict__[builtin]
        safe_builtins = ReadOnlyBuiltins(original_builtins)
        sys.modules["__main__"].__dict__["__builtins__"] = safe_builtins
        if hasattr(sys.modules["__main__"], "__file__"):
            del sys.modules["__main__"].__file__
        if hasattr(sys.modules["__main__"], "__loader__"):
            del sys.modules["__main__"].__loader__
        for key in [
            "__loader__",
            "__spec__",
            "origin",
            "__file__",
            "__cached__",
            "ReadOnlyBuiltins",
            "Sandbox",
        ]:
            if key in sys.modules["__main__"].__dict__["__builtins__"]["open"].__globals__:
                del sys.modules["__main__"].__dict__["__builtins__"]["open"].__globals__[key]
