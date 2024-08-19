# Irrandomcible

Category | Author | Solves | Points
-------- | ------ | -----: | -----:
Crypto   | A~Z    | ?      | ?

> A crane flew by, and delivered this baby chall.
I can't understand a word it speaks.


## The questions of `README.md`


- Let $X=\mathbb P^1_F$. What is the function field $K(X)$ of $X$?

The function field of an integral curve is the field of rational functions, where a rational function $f$ is a regular map (read: "function defined by polynomials") that's defined over some dense open set.
In the case of the projective line, these are exactly the degree $0$ homogeneous rational functions in $x$ and $y$, by which I mean quotients of the form $$f(x,y)=P(x,y)/Q(x,y)$$ where $P$ and $Q$ are homogeneous polynomials of the same degree.
Evaluating at $y=1$ (equivalently, placing ourselve on the affine patch $\mathbb A^1_F\simeq\{y\neq0\}$) gives an isomorphism to the field $F(x)$.


- What is the structure sheaf $\mathscr O_X$ of $X$?

This question is not required to solve the chall.

We may understand $\mathbb P^1_F$ as the gluing of two affine lines $\mathbb A^1_F$.
Calling these $D_x=\{x\neq 0\}$ and $D_y=\{y\neq 0\}$, we have that $\mathscr O_X|D_x = O_{D_x}$ and similarly for $D_y$, so that it suffices to understand the structure sheaf of the affine line.
A basis of open sets for the latter is given by the $D_f={f\neq 0}$ where $f\in F[t]$ is a polynomial; on every one of these sets we have $$\mathscr O_{\mathbb A^1_F}(D_f) = F[t]_f := F[t, 1/f].$$


- What are the global sections $\mathscr O_X(X)$ of $\mathscr O_X$?

A global section of the structure sheaf $\mathscr O_X(X)$ is a regular map on $X$.
For $\mathbb P^1_F$, such a map is always constant: $\mathscr O_X(X) = F$.

The previous question gives us enough information to prove this fact.
If $f\in\mathscr O_X(X)$, then we can look at its restrictions $$f|D_x\in\mathscr O_X(D_x)=F[y] \quad\text{and}\quad f|D_y\in\mathscr O_X(D_y)=F[x].$$
Moreover the gluing is done over the set $D_{xy}=\{xy\neq 0\}$, which can be understood in $D_x$ as the open $\{y\neq0\}$ and in $D_y$ as $\{x\neq0\}$.
The transition map between $\mathscr O_{D_x}(D_{xy)}=F[y,1/y]$ and $\mathscr O_{D_y}(D_{xy)}=F[x,1/x]$ is given by sending $y\mapsto 1/x$ and conversely.

Hence for $f$ to be simultaneously well defined as an element of $F[x]$ and $F[y]=F[1/x]$, it must be constant.


- What is a vector bundle? (in algebraic geometry)

There are several ways to understand them.
The most elementary is to consider a morphism $p:E\to X$ from some sort of space $E$ to $X$, and say that $p$ is a vector bundle of rank $n$ if $X$ can be covered by open sets $U$ such that $E|_U:=p^{-1}(U)$ is homeomorphic over $U$ to $U\times F^n$, subject to some coherence condition ensuring that for $x\in X$ the vector space structure of $$E(x):=p^{-1}(x)\simeq x\times F^n$$ depends not on the choice of homeomorphism.

In this way, a vector bundle is a space above $X$ that locally looks like a vector space times $X$.

Another equivalent way (warning: the equivalence is not easy to prove without developing a lot more tools) is to say that a vector bundle of rank $n$ is an $\mathscr O_X$-module locally isomorphic to $\mathscr O_X^n$.

Under the equivalence, the trivial bundle $X\times F^n\to X$ corresponds to the trivial bundle $\mathscr O_X^n$.


- Let $V$ a vector bundle over $X$. What does $H^0(X,V)$ mean?

We write $H^0(X,V)$ for the set of global sections of $V$.
Assuming the elementary pov $p:V\to X$, a global section $s$ is a morphism $s:X\to V$ for which $ps=1_X$.
In other words, $s$ is a morphism sending $x$ to an element of $V(x)$.
The set $H^0(X,V)$ has an $F$-vector space structure inherited from that of $V(x)$.

In the less elementary pov, the global sections of $V$ are $H^0(X,V)=V(X)$.


- What is $\mathscr O(m)$, with respect to $\mathscr O(1)$? (where $m\in\mathbb Z$)

Just as we can define tensor products of vector spaces, so can we tensor products of vector bundles.
In the same way we can also define the dual vector bundle.

In the not-elementary pov, the tensor product of $V$ and $W$ is their tensor product as $\mathscr O_X$-modules.
The dual of $V$ is the bundle $$V^\vee:=\underline{\operatorname{Hom}}(V,\mathscr O_X).$$
The elementary pov requires a bit more care to properly define things, and to be honest I'm a bit too lazy to think it through (also this writeup is too long already).

When $m\geq0$ we define $$O(m)=O(1)^{\otimes m}:=\bigotimes_{i=1}^m O(1),$$ with the convention that $O(1)^{\otimes 0}$ is the trivial bundle.
Then $$O(-m):=O(m)^\vee=O(-1)^{\otimes m}.$$


- Can you describe explicitly the global sections of $\mathscr O(m)$?

These are the homogenenous polynomials of degree $m$ when $m\geq0$, and $0$ otherwise.
An $F$-basis is given by the monomials $x^iy^j$ where $i+j=m$.
As such, $H^0(X, \mathscr O(m))$ has dimension $m+1$.


- If $V$ and $W$ are two vector bundles, what is $H^0(X,V\oplus W)$ with respect to $H^0(X,V)$ and $H^0(X,W)$?

We simply have $H^0(X,V\oplus W) = H^0(X,V) \oplus H^0(X,V)$.


## Approaching the challenge

The challenge runs the following step:
- generate a random password $(a_i)$
- let $K = F(x) \simeq K(\mathbb P^1_F)$, where $F=\mathbb F_p$
- let $L = O(-1)$, a vector bundle over $\mathbb P^1_F$
- compute $V=\bigoplus_i L^{\otimes a_i} = \bigoplus_i O(-a_i)$
- let $L = O(1)$
- compute $\dim H^0(\mathbb P^1_F, V\otimes O(m))$ for lots of $m$
- output these dimensions
- the goal is to find the password (possibly shuffled)

Recalling the questions, we know the following:
$$\begin{aligned}
\dim H^0(X, V\otimes O(m)) &= \dim H^0(X, \bigoplus_i O(m-a_i)) \\
&= \dim \bigoplus_i H^0(X, O(m-a_i)) \\
&= \sum_i \dim H^0(X, O(m-a_i)) \\
&= \sum_{a_i\geq m} m-a_i+1
.\end{aligned}$$

Now the solve is pretty simple!
We just need to iterate over the $m$-s for which we know the dimension, track the contributions of each character, and check whenever we have some new contribution.

Full solve in [`solve.py`](./debug/solve.py) (running time: instant).