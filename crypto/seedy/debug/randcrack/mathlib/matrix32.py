import gmpy2
from copy import deepcopy

"""
    Matrices here are represented as
    lists of gmpy2.mpz(x)s.

    (I created 2 files because I'm lazy)
"""

def add_mat32(M, N):
    """
        add_mat64(): Adding 2 32x32 matrices.
    """
    R = deepcopy(M)
    for i in range(32):
        R[i] ^= N[i]
    return R

def mul_mat32(M, N):
    """
        mul_mat64(): Multiply 2 32x32 matrices.
    """
    M = deepcopy(M)
    R = [gmpy2.mpz(0)] * 32
    for i_row in range(32):
        for i_col in range(32):
            if gmpy2.bit_test(M[i_row], 0):
                R[i_row] ^= N[i_col]
            M[i_row] >>= 1
    return R

def mul_vecl32(v, M):
    """
        mul_vecl32(): Multiply a vector v of 32 items
                      with a 32x32 matrix M (v*M)
    """
    v = deepcopy(v)
    r = gmpy2.mpz(0)
    for i_row in range(32):
        if gmpy2.bit_test(v, 0):
            r ^= M[i_row]
        v >>= 1
    return r