from sage.all import *
from pwn import remote
from itertools import chain

F2 = GF(2)
n = 4800
ku = 1484
kv = 916
assert (2 * ku - kv <= n//2)

# The following is a slightly modified version of 
# https://github.com/vvasseur/pqsigRM/blob/master/find_U_UV.py
def compute_equations(GPJ):
    N = GPJ.ncols()
    R = N // 2

    dim_VA = GPJ[:, :R].rank()
    dim_U = GPJ[dim_VA:, R:].rank()
    len_U2 = R - dim_U
    pivots_U = GPJ[dim_VA:, R:].pivots()
    supp_U2 = [R + i for i in range(R) if i not in pivots_U]

    # The permutation of two matched pairs in GP is in fact a linear operation
    # on GP * J. In this loop we precompute all the differences.
    equations_row = [matrix(GF(2), R, len_U2) for i in range(dim_VA)]
    for i in range(R):
        column_left = GPJ[:dim_VA, i]
        support_indices = [j for j, cj in enumerate(column_left) if cj[0] == 1]
        if i in pivots_U:
            r = pivots_U.index(i)
            row_right = GPJ[dim_VA + r, supp_U2]
            for j in support_indices:
                equations_row[j][i] = row_right
        else:
            i2 = supp_U2.index(R + i)
            for j in support_indices:
                equations_row[j][i, i2] = 1

    return equations_row, supp_U2

def apply_swaps(permutation, swaps):
    permutation_swapped = permutation[:]
    k = len(swaps)
    for i in range(0, len(permutation), 2 * k):
        for j in range(k):
            if swaps[j]:
                permutation_swapped[i + j], permutation_swapped[i + j + k] = (
                    permutation_swapped[i + j + k],
                    permutation_swapped[i + j],
                )
    return permutation_swapped


def find_swaps(GP, dimA=0):
    N = GP.ncols()
    R = N // 2

    J = matrix.block(
        [
            [matrix.identity(GF(2), R), matrix.identity(GF(2), R)],
            [matrix.identity(GF(2), R), 0],
        ]
    )

    swaps = [0 for _ in range(R)]

    GPJ = GP * J
    GPJ.echelonize()

    # The left side of GPJ has a rank equal to the dimension of V + A.
    # (A is the span of the appended rows.)
    dim_VA = GPJ[:, :R].rank()

    equations_row, supp_U2 = compute_equations(GPJ)

    # This heuristic finds a permutation while handling the appended rows. In
    # the end, the submatrix in the upper right corner of GPJ should have a
    # rank equal to `K_APP`.
    # For each row, a linear system can be solved to find suitable column
    # swapping that cancels that row if its component on A is zero. If not, we
    # append the row to our system, hoping that it is a vector of a basis of A.
    rank = GPJ[:dim_VA, R:].rank()
    while rank > dimA:
        print(rank)
        unsolved = []
        for j in range(dim_VA):
            if vector(GPJ[j, supp_U2]) == 0:
                continue

            A = equations_row[j]
            if unsolved:
                A = A.stack(GPJ[unsolved, supp_U2])

            try:
                sol = A.solve_left(vector(GPJ[j, supp_U2]))
            except Exception:
                unsolved.append(j)
                pass
            else:
                if sol[:R] != 0:
                    for i, pi in enumerate(sol[:R]):
                        if pi == 1:
                            GPJ[:, i + R] += GPJ[:, i]
                            swaps[i] ^= 1
                    GPJ.echelonize()

        rank = GPJ[:dim_VA, R:].rank()
    return swaps

def prange_1(H, w, s):
    n = H.ncols() * 2
    for ind in range(n//2):
        pivots = H[:, ind:].pivots()
        pivots = [ind + x for x in pivots]

        try:
            e2 = H[:, pivots].solve_right(s)
        except:
            continue
        if e2.hamming_weight() == w:
            print("FOUND", ind)
            e = [0 for _ in range(n//2)]
            for i in range(len(pivots)):
                e[pivots[i]] = e2[i]
            e = vector(F2, e)
            assert(H * e == s)
            return e
    print("NOT FOUND")
    sys.exit(1)


def prange_2(H, w, s, x):
    n = H.ncols() * 2
    rho = x.hamming_weight()
    supp = x.support()
    perm = supp + [i for i in range(n//2) if i not in supp]

    Ht = H[:, perm]
    Htr = Ht.echelon_form()
    S = Ht.solve_left(Htr)

    Ht1 = Htr[:rho, rho:]
    Ht2 = Htr[rho:, rho:]
    sr = S * s
    sp1 = vector(F2, sr[:rho])
    sp2 = vector(F2, sr[rho:])
    e2 = prange_1(Ht2, w, sp2)
    e1 = sp1 + Ht1 * e2

    e = vector(F2, list(e1) + list(e2))
    e = vector(F2, [e[perm.index(i)] for i in range(n//2)])
    assert len(set(e.support()) - set(x.support())) == w
    assert (H * e == s)
    return e

for ___ in range(3):
    # io = process(["sage", "--notdotsage", "chall.sage"])
    io = remote('localhost', 1337)
    io.recvline()
    # Currently makes the healthcheck fail, there is no chall.sage
    try:
        io.sendlineafter(b'choice: ', b'pkey')
        Hpub = loads(bytes.fromhex(io.recvline(False).decode()))


        # Fetch the parity check matrix of the dual of Hpub
        # This is the generator matrix of the code
        Hdual = Hpub.right_kernel().basis_matrix()
        FF = Hdual.stack(Hpub)
        hull = FF.right_kernel().basis_matrix()
        hullt = hull.T

        # Recover column by column
        zeros = [i for i in range(n) if hull[0][i] == 0]
        ones = [i for i in range(n) if hull[0][i] == 1]
        recov = []

        import itertools 

        for a, b in itertools.combinations(zeros, 2):
            if hullt[a] == hullt[b]:
                recov.append((a, b))
        print("DONE P1")

        for a, b in itertools.combinations(ones, 2):
            if hullt[a] == hullt[b]:
                recov.append((a, b))
        print("DONE P2")

        pairs = {(min(x), max(x)) for x in recov}
        permutation = list(chain.from_iterable(zip(*pairs)))

        G = Hpub.right_kernel().basis_matrix()
        Gpub = G
        swaps = find_swaps(G[:, permutation])
        permutation = apply_swaps(permutation, swaps)

        GPp = Gpub[:, permutation]
        row0 = GPp[:, :n//2] + GPp[:, n//2:]
        shi = row0.left_kernel().basis_matrix()
        slo = GPp[:, :n//2].left_kernel().basis_matrix()

        #This is an equivalent decomposition of the public key
        Seqinv = (shi.stack(slo))
        Peqinv = Matrix(F2, [[1 if i == permutation[j] else 0 for j in range(n)] for i in range(n)], implementation = "m4ri")
        Peq = Peqinv**-1

        Gseq = Seqinv * Gpub * Peqinv

        # Check Gseq is a generator matrix of a (U, U+V) code.
        assert(Gseq[:ku, :n//2] == Gseq[:ku, n//2:])
        assert(Gseq[ku:, :n//2] == 0)

        Gu = Gseq[:ku, :n//2]
        Gv = Gseq[ku:, n//2:]
        Hu = Gu.right_kernel().basis_matrix()
        Hv = Gv.right_kernel().basis_matrix()

        Hs = block_matrix(F2, [
                            [Hu, 0],
                            [Hv, Hv]])

        Seq = (Hs * Peq).solve_left(Hpub)
        Seqinv = Seq**-1
        assert Seq * Hs * Peq == Hpub

        print("VALID DECOMP!")

        from hashlib import shake_256
        import sys


        msg = b'gimme the flag!'
        s = shake_256(msg).digest(n//16)
        s = int.from_bytes(s, 'big')
        s = vector(F2, list(map(int, bin(s)[2:].zfill(8))))
        Ss = Seqinv * s

        #Step 1
        s2 = vector(F2, Ss[kv:])
        w2 = ku//2
        ev = prange_1(Hv, w2, s2)

        s1 = vector(F2, Ss[:kv])
        w1 = (kv - ev.hamming_weight())//2
        eu = prange_2(Hu, w1, s1, ev)

        e = vector(F2, list(eu) + list(eu + ev))
        eP = e * Peq
        assert(Hpub * eP == s)

        io.sendlineafter(b'choice: ', b'verify')
        io.sendlineafter(b'msg: ', msg)
        io.sendline(str(eP).encode())
        out = io.recvall(2)
        if b'idek' in out:
            exit(0)
    except Exception as e:
        io.close()

exit(1)

