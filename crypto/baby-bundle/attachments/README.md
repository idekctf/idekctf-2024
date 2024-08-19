# The `vector_bundle` lib

The `vector_bundle` library comes from the paper *Algebraic algorithms for vector bundles over curves* by [Mickaël Montessinos](http://mickael.montessinos.fr/).
You can find both the code and documentation on his website, together with said paper.
The installation instructions are very clear!

### Optional for solving the chall

In order to understand how the vector bundles are actually represented there,
I recommend looking at subsection 4.1 (*Algorithmic representation of lattice pairs*) and backtracking to section 3 for notations.
Being familiar with vector bundles will help.
This is not important right now, but will prove very useful for the next chall.
By the way, said next chall will involve subsection 5.1 (*Vector bundles on an elliptic curve*), as well as Atiyah's [paper](https://math.berkeley.edu/~nadler/atiyah.classification.pdf) (reference [3] in Montessino's paper).

# What the heck is going on? I have no idea what this chall does

For people familiar with projective schemes, this challenge is not very challenging.
If you aren't, it is my hope that you still manage to solve it after some research.
Hopefully you'll pick up some nice tidbits along the way!

The theory can look extremely daunting.
It is also very vast, making it easy to get lost.
Here are some questions whose answers might or might not greatly help you:
- Let $X=\mathbb P^1_F$. What is the function field $K(X)$ of $X$?
- What is the structure sheaf $\mathscr O_X$ of $X$?

Surprisingly, the above question is not actually mandatory for solving.
Even without understanding it you can still answer the below question.
- What are the global sections $\mathscr O_X(X)$ of $\mathscr O_X$?
- What is a vector bundle? (in algebraic geometry)

For the above question, Savin described an elementary point of view in his [paper](https://arxiv.org/pdf/0803.1096v1).
The mainstream point of view requires understanding $\mathscr O_X$ precisely.
The following question depends on the way you chose to understand vector bundles, and is very important for the chall.
- Let $V$ a vector bundle over $X$. What does $H^0(X,V)$ mean?

Over $\mathbb P^1_F$ there is a very interesting bundle, called $\mathscr O(1)$.
Understanding its precise definition is optional.
- What is $\mathscr O(m)$, with respect to $\mathscr O(1)$? (where $m\in\mathbb Z$)
- Can you describe explicitly the global sections of $\mathscr O(m)$?
- If $V$ and $W$ are two vector bundles, what is $H^0(X,V\oplus W)$ with respect to $H^0(X,V)$ and $H^0(X,W)$?
