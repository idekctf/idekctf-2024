# Tensor Galore

Category | Author | Solves | Points
-------- | ------ | -----: | -----:
Crypto   | A~Z    | ?      | ?

> CSIDH is *so* 2018. Wake up babe, new class group action just dropped.


## Approaching the chall

Lots of setup, but basically the challenge deals with vector bundles over some elliptic curve $C$.
It implements a diffie-hellman like scheme operating on the isomorphism classes of rank $4$ degree $1$ vector bundles, as follow:
- generate a base bundle $E_0$ (pf rank $4$ and degree $1$).
- generate random line bundles $L_A$ and $L_B$ (private keys of alice and bob).
- compute $E_A\simeq E_0\otimes L_A$ and $E_B\simeq E_0\otimes L_B$.
- compute $E_{AB}\simeq E_A\otimes L_B$ and $E_{BA}\simeq E_B\otimes L_A$.
- derive a shared secret based on the isomorphism class of $E_{AB}$ and $E_{BA}$ (these two are indeed isomorphic).
- give $E_0$, $E_A$, $E_B$ to the player.
- the goal is to find a bundle isomorphic to $E_{AB}$ and $E_{BA}$.


## Solving it

Before delving straight into the chall, let me explain some things about the relation between Weil divisors and line bundles.


### Divisors

A Weil divisor over $C$ is a formal sum $$D = \sum_{P\in C}n_P[P],$$ where $n_P\in\mathbb Z$ are almost all $0$.
Beware that the points $P$ appearing in this sum might only be defined over some finite field extension of the base field $F$.
We call $\operatorname{Div}(C)$ the group of divisors.

The points $P\neq 0$ of $C$ correspond bijectively to maximal ideals $\mathfrak m_P$ of the maximal order $\mathcal O$ of $K,$ where $K=F(x,y)/(y^2-x^3-ax-b)$ is the function field of $C.$
The point at infinity is the maximal ideal of the infinite maximal order $\mathcal O_\infty$ of $K$.
Moreover, every fractional ideal $\mathfrak a\neq0$ of $\mathcal O$ may be factored uniquely as a product $$\mathfrak a=\prod_P \mathfrak m_P^{n_P}$$ with almost all $n_P=0.$
Hence we can associate $\mathfrak a$ to a divisor $$\operatorname{div}\mathfrak a\coloneqq\sum_P n_P[P].$$
In the same way any non-zero fractional ideal of the maximal infinite order can be written in the form $\mathfrak m_\infty^n$ for some unique $n\in\mathbb Z$ and corresponds to the divisor $n[0]$.

If $f\in K^\times$ is a non-zero rational function on $C$, the *divisor of $f$* is $$\operatorname{div} f\coloneqq\sum_i n_i[P_i]-\sum_j m_j[Q_j]$$ where $P_i$ stand for zeroes of multiplicity $n_i$ and $Q_j$ poles of multiplicity $m_j$.
It can be shown in fact that $$\operatorname{div} f=\operatorname{div} f\mathcal O+\operatorname{div} f\mathcal O_\infty.$$
A divisor of the form $\operatorname{div}f$ is called *principal*.
As $\operatorname{div}(fg)=\operatorname{div}f+\operatorname{div}g$, principal divisors form a subgroup of $\operatorname{Div}C$ denoted by $\operatorname{Prin}C.$
We define the *picard group* $\operatorname{Pic}C$ as the quotient $$\operatorname{Pic}C\coloneqq\operatorname{Div}C/\operatorname{Prin}C.$$

To every divisor $D=\sum_P n_P[P]$ can be associated an invariant, the degree $$\operatorname{deg}D=\sum_P n_P\cdot\operatorname{deg}P,$$ where the degree of $P\in C$ is the degree of the smallest field extension of $F$ over which $P$ is defined.
It can be shown that on projective curves (such as elliptic curves), principal divisors always have degree $0$, and thus we can consider the very interesting subgroup $$\operatorname{Pic}^0C=\{D\in\operatorname{Pic}C\ \text{ s.t.}\ \operatorname{deg}D=0\}.$$
We will see a bit later that $\operatorname{Pic}^0C$ is none other than the group of points of $C$.


### Line bundles

To every divisor $D$ can be associated a line bundle $\mathscr L(D)$, whose definition will not be given here.
It turns out that not only is every line bundle of this form, but $\mathscr L(D)\simeq\mathscr L(D')$ if and only if $D'=D+\operatorname{div}f$ for some $f\in K^\times$.
Moreover, one can prove that $\mathscr L(D)\otimes\mathscr L(D')\simeq\mathscr L(D+D')$ !
As such, if we write $$\operatorname{Cl}(C)=\left\{\text{ iso classes of line bundles }\right\}$$ for the *class group* of $C$ (with multiplication given by the tensor product), the map $D\mapsto\mathscr L(D)$ yields an isomorphism $$\operatorname{Pic}C=\operatorname{Div}C/\operatorname{Prin}C\xrightarrow\sim\operatorname{Cl}(C)$$ between the *picard group* and the *class group*.
It's a very important isomorphism!


### The case of elliptic curves

If $3$ points $P, Q, R\in C$ lie on the same line, which is to say that $P+Q+R=0$, then there is a rational function $f$ annihilated exactly at these points (and with $3$ poles at infinity).
This means that $$\operatorname{div}f=[P]+[Q]+[R]-3[0].$$
In particular, we deduce that $[P]+[Q]+[R]=3[0]$ as elements of $\operatorname{Pic}C$.
For instance, considering the same equality for $R,-R,0$ yields $[R]+[-R]=2[0]$.
Injecting this back and recalling that $-R=P+Q$ gives $$[P]+[Q]=[P+Q]+[0]\in\operatorname{Pic}C.$$

<center><h4>Slogan: actually computing the addition of points on the elliptic curve allows you to reduce divisors.</h4></center>

As such, any divisor $D$ can be written in the form $D=[P]-n[0]$ in $\operatorname{Pic}C$.
We can in fact prove that this form is unique.
When $D$ has degree $0$, we have that $n=\deg P$.
The arrow $$P\mapsto D_P\coloneqq[P]-(\deg P)[0]$$ thus completes the earlier isomorphism of groups in a series that link together the curve and the degree $0$ line bundles: $$\begin{array}{}
C &\xrightarrow\sim &\operatorname{Pic}^0C &\xrightarrow\sim &\operatorname{Cl}^0C \\
P &\longmapsto &D_P &\longmapsto &\mathscr L(D_P)
\end{array}.$$

## Application to the challenge

In Atiyah's paper [Vector bundles over an elliptic curve](https://math.berkeley.edu/~nadler/atiyah.classification.pdf), these isomorphisms get greatly generalised.
A vector bundle $\mathscr E$ is indecomposable if it cannot be written as a non-trivial sum $\mathscr E=\mathscr F\oplus\mathscr G$, and absolutely so if it is indecomposable over the algebraic closure of $F$.
The set $E(r,d)$ of isomorphism classes of absolutely indecomposable bundles of rank $r$ and degree $d$ is acted upon by the degree $0$ class group $\operatorname{Cl}^0C$, using the tensor product.

According to Theorem 7 (page 434), we can identify every $E(r,d)$ with $C$ in such a way that:
- if $\mathscr E\in E(r,d)$ corresponds to $P$, then $\mathscr E\otimes\mathscr L(D_Q)$ corresponds to $P+rQ$.
- the determinant $\operatorname{det}:E(r,d)\to E(1,d)$ corresponds on $C$ to multiplication by $h=\gcd(r,d)$.
- if $h=1$, then the determinant is a bijection.

Recall the setting of the challenge: we are given $\mathscr E_0,\mathscr E_A,\mathscr E_B\in E(4,1)$ such that $\mathscr E_A\simeq\mathscr E_0\otimes\mathscr L_A$ and $\mathscr E_B\simeq\mathscr E_0\otimes\mathscr L_B$.
We want to find the isomorphism class of $L_A$ and thus break the key exchange.
Considering that $$\det\mathscr E_A=\det\mathscr E_0\otimes\mathscr L_A^4,$$ mapping $\mathscr E_0$ and $\mathscr E_A$ to the corresponding points $P_0$ and $P_A$ on $C$ will turn the problem into solving the equation $P_A=P_0+4Q_A$ for the point $Q_A$ corresponding to $\mathscr L_A$.
Such an equation is very easy to solve.

---

It remains to understand how to actually map a bundle to the corresponding point.
Delving into the [specifics](https://arxiv.org/abs/2403.09449) of Montessinos' implementation, we find in subsection 4.1 that vectors bundle of rank $r$ are represented as triples $$g=((\mathfrak a_i)_{1\leq i\leq r},g_\textsf{fin},g_\textsf{inf});$$ in which $\mathfrak a_i$ are fractional ideals of the maximal order $\mathcal O$, and $g_\textsf{fin}$ and $g_\textsf{inf}$ square $r$-matrices.
Such a triple induces the "lattice pair" $\operatorname{LP}(g)=(L_\textsf{fin},L_\textsf{inf})$, where if $x_1\ldots x_r$ are the columns of $g_\textsf{fin}$ then $$L_\textsf{fin}=\mathfrak a_1x_1\oplus\ldots\oplus\mathfrak a_rx_r\quad\text{and}\quad L_\textsf{inf}=g_\textsf{inf}\mathcal O_\infty^r.$$
Note that one could as discussed in section 3 of Montessinos' paper, we may treat $\operatorname{LP}(g)$ as a vector bundle.
In rank $1$, this representation devolves to $L_\textsf{fin}$ and $L_\textsf{inf}$ simply being fractional ideals of $\mathcal O$ and $\mathcal O_\infty$ respectively.
How can we turn a triple inducing a lattice pair (of rank 1) into the point we're interested in?
Computing the divisor in $\operatorname{Cl}C$ gives $$\operatorname{div}\operatorname{LP}(\mathfrak a,g_\textsf{fin},g_\textsf{inf})=\operatorname{div}(g_\textsf{fin}\mathfrak a)+\operatorname{div}L_\textsf{inf}=\operatorname{div}\mathfrak a+\operatorname{div}L_\textsf{inf}=[Q]-n[0]$$ for some $Q$.
Remark that as an ideal of $\mathcal O_\infty$, the divisor of $L_\textsf{inf}$ only contributes to the $n[0]$ part; it is useless if we care only for $Q$.
All of these observations combine to the desired algorithm!

**INPUT:** an isomorphism class $\mathscr E\in E(r,d)$, such that $\gcd(r,d)$ is invertible modulo $\# C(F)$.

**STEPS:**
1. Let $\mathscr L=\det\mathscr E$, as represented by a triple $(\mathfrak a,g_\textsf{fin},g_\textsf{inf})$.
1. Let $D=\operatorname{div}\mathfrak a=\sum_P n_P[P]$
1. Let $Q=\sum_P n_PP$.
1. Let $h=\gcd(r,d)$
1. Return $Q/h$.

There is a slight problem however, in that the points appearing may have degree greater than $1$ (ie. they are only defined over some extension of $F$).
Thus if we want to be able to sum them, we'll have to consider $P$ in some large enough extensions.
In practice, going to degree $12$ worked.

```py
Fe = GF(q**12 , 'a')
Ce = EllipticCurve(Fe, [a, b])
Ke = EllipticFunctionField(Ce)
xe = Ke.base_field().gen()
ye = Ke.gen()
Oe = Ke.maximal_order()

_f = K.base_field().hom([xe])
f  = K.hom([ye], _f)
Ke.base_field().register_coercion(_f)
Ke.register_coercion(f)


def point_from_bundle(E, d):
    # d: degree of E
    L = E.determinant()                     # point(E) = h * point(L)
    D = L.coefficient_ideals()[0].divisor() # D = div a
    P = Ce(0)
    for p, m in D.list():                   # D = sum m[p]
        Ie = p.prime_ideal() * Oe           # split in extension
        for pe, _ in Ie.divisor().list():   # get points in extension
            X, Y = pe.prime_ideal().gens()  # extract point coordinates
            P += m * Ce(xe-X, ye-Y)

    if d < 0:                               # dual something or something
        P = -P
    h = gcd(E.rank(), d)                    # we need to divide by h
    return P.change_ring(F).division_points(h)[0]
```

Luckily the map back from point to bundle is not so complicated, because it is mostly implemented out-of-the-box in Montessinos' `vector_bundle` library.

```py
def bundle_from_point(P, r, d):
    P = O.ideal(x - P.x(), y - P.y()).place() # [P]
    L = VectorBundle(K, Inf - P)              # L([P] - [0])
    return atiyah_bundle(K, r, d, L)          # bundle(P)
```

And now we have all the tools at our disposal to break the Diffie-Hellman!
```py
io.recvuntil(b'-'*20 + b'\n')

E0, EA, EB = [
    parse_bundle(io.recvline(False).decode())
    for _ in range(3)
]

r,d = 4,1
P = point_from_bundle(E0, d)
Q = point_from_bundle(EA, d)

RA  = (Q-P).division_points(r)[0] # Q = P + r*RA
LA  = bundle_from_point(RA, 1, 0) # myLA^r ~= LA^r
EBA = EB * LA                     # myEBA  ~= EBA

io.sendline(dump_bundle(EBA).encode())
```
Full solve in [`healthcheck.sage`](./healthcheck/healthcheck.sage) (running time: <30s, after alarm: <2.3s)