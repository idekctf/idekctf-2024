# The vuln is not there, this is just a helper that you can blackbox.
# This class achieves huge speedups over the generic implementation by specifying explicit
# bases instead of computing them.


from sage.rings.function_field.function_field_rational import RationalFunctionField_global
from sage.rings.function_field.function_field_polymod import FunctionField_global_integral


class EllipticFunctionField(FunctionField_global_integral):
    """
    Function fields of an elliptic curve.
    Only tested for elliptic curves over finite fields for now.

    INPUT:

    - ``curve`` -- an elliptic curve over a field
    """

    def __init__(self, curve, names=None):
        from sage.rings.polynomial.polynomial_ring import polygen
        if names is None:
            names = ('y',)

        self._curve = curve.short_weierstrass_model()
        _, _, _, a, b = self._curve.ainvs()

        K = RationalFunctionField_global(curve.base_field(), 'x')
        x = K.gen()
        poly = polygen(K, names)**2 - x**3 - a*x - b

        FunctionField_global_integral.__init__(self, poly, names=names)

    def curve(self):
        """
        Return the elliptic curve associated to the function field.
        """
        return self._curve

    def maximal_order_infinite(self):
        """
        Return the maximal infinite order of the function field.
        """
        return FunctionFieldMaximalOrderInfinite_elliptic(self)

    def _maximal_order_basis(self):
        return [self.one(), self.gen()]

    def _inversion_isomorphism(self):
        iF, from_iF, to_iF = super()._inversion_isomorphism()

        x = iF.base_field().gen()
        s = iF.gen()
        iF._maximal_order_basis = lambda *_: [iF.one(), s/x] # huge speedup

        return iF, from_iF, to_iF


from sage.rings.function_field.ideal_polymod import FunctionFieldIdealInfinite_polymod
from sage.rings.function_field.order_polymod import FunctionFieldMaximalOrderInfinite_polymod
from sage.rings.function_field.order import FunctionFieldMaximalOrderInfinite


class FunctionFieldMaximalOrderInfinite_elliptic(FunctionFieldMaximalOrderInfinite_polymod):
    """
    Maximal orders of elliptic function fields.

    INPUT:

    - ``field`` -- elliptic function field
    """

    def __init__(self, field, category=None):
        """
        Initialize.
        Copied from ``FunctionFieldMaximalOrderInfinite_polymod.__init__``.
        """
        FunctionFieldMaximalOrderInfinite.__init__(self, field, ideal_class=FunctionFieldIdealInfinite_polymod)

        y = field.gen()
        x = field.base_field().gen()
        self._basis = (field.one(), y/x**2) # huge speedup

        V, from_V, to_V = field.vector_space()
        R = field.base_field().maximal_order_infinite()

        self._module = V.span_of_basis([to_V(v) for v in self._basis])
        self._module_base_ring = R
        self._to_module = to_V
