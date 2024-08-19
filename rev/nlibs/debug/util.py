class TransformVisitor(object):
    _method_cache = None

    def visit(self, node, parent=None):
        """ Visit a node.
        """

        if self._method_cache is None:
            self._method_cache = {}

        cb = self._method_cache.get(node.__class__.__name__, None)
        if cb is None:
            method = 'visit_' + node.__class__.__name__
            cb = getattr(self, method, lambda x: None)
            self._method_cache[node.__class__.__name__] = cb

        return self.generic_visit(node, cb, parent)

    def generic_visit(self, node, cb, parent=None):
        setattrs = []
        setitems = []
        if node is None:
            return node
        for k, c in enumerate(node):
            ret = self.visit(c, node)
            if ret:
                for name in node.__slots__[:-2]:
                    attr = getattr(node, name, None)
                    if isinstance(attr, type(c)) and attr == c:
                        setattrs.append((name, ret))
                    elif isinstance(attr, list) and k < len(attr) and attr[k] == c:
                        setitems.append((name, k, ret))

        for name, ret in setattrs:
            setattr(node, name, ret)
        for name, i, v in setitems:
            getattr(node, name)[i] = v
        self.parent = parent
        new_node = cb(node)
        if new_node:
            node = new_node
        return node