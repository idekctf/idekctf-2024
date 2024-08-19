# Irrandomcible

Category | Author | Solves | Points
-------- | ------ | -----: | -----:
Crypto   | A~Z    | ?      | ?

> > And in the left corner! Beer in hand, degen anime in mind! You all recognize him, the drunk cryptoman!! SOOOOOOOOOON HAAAAAARRIIIIIIII
>
> While attempting to become as good as my idol Haari-sama of the Soon clan, I got drunk and randomized the flag. Please help.

## Approaching the chall

The chall basically runs the following steps:
- generate a random integer $5 \leq n \leq 10$
- generate a random subgroup $G$ of $S_n$
- generate a random prime $p$ with around $32$ bits

With overwhelming probability, the cardinal of $G$ is coprime to $p$.
- generate a random non-trivial irrep of $G$, of degree $n$
- compute the image of $G$ in $M_n(\mathbb F_p)$, disregarding the unit element

This assumes that the representation has integer coefficients, so it doesn't work every time.
- cuts the flag in length $n$ blocks, and for each block $b$:
- multiply $b$ by a random element $\lambda$ of $\mathbb F_p$
- compute the orbit of $\lambda b$ under the action of $G$, disregarding the unit element
- output the orbit

## Solving it

This chall is actually pretty stupid.
All of this random might look daunting, but it gets destroyed by a single observation.
Consider the element $$R_G=\dfrac1{|G|}\sum_{g\in G} g\in M_n(\mathbb F_p).$$
Then for every $h\in G$ and $v\in \mathbb F_p^n$, we have that $$hR_Gv=\dfrac1{|G|}\sum_{g\in G}hgv=\dfrac1{|G|}\sum_{g\in G}gv=R_Gv.$$
In other words, the image of $R_G$ is a subrepresentation.
But the point of irreducible representations is that they have no non-trivial subrepresentations, so that $R_G$ is either $0$ or surjective.
The latter case is impossible, as it would imply that $G$ acts trivially (if $v\in\mathbb F_p^n$ and $g\in G$, then there is $w$ with $v=R_Gw$ and $gv=gR_Gw=R_Gw=v$), a case we excluded when choosing the irrep.

As such, we proved that $R_Gv-v=-v$.
But for $v=\lambda b$, we are given all the $gv$ except for $v$.
Their sum is exactly $R_Gv-v=-v=-\lambda b$.
Of course, we still don't know $p$ nor $\lambda$.
This is not a problem, as the flag format allows for bruteforcing the former.
Then the latter is deduced by bruteforcing the first character of each block.

Full solve in [`solve.sage`](./debug/solve.sage) (running time: instant).