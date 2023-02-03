No, $|x|_q$ and $\lfloor x \rfloor_q$ are not the same thing.

$|x|_q$ is the residue of x modulo q, which is the unique representative of x in the set of integers mod q, which is the set of integers between 0 and q-1. For example, if $q = 7$, then $|5|_q = 5$, $|12|_q = 5$, $|-2|_q = 5$, and so on.

On the other hand, $\lfloor x \rfloor_q$ is the greatest integer less than or equal to x that is congruent to x modulo q. It's the floor function applied to x mod q. This notation returns the greatest integer in the set of integers mod q that is less than or equal to x. For example if q = 7, $\lfloor 5 \rfloor_q = 5$, $\lfloor 12 \rfloor_q = 5$, $\lfloor -2 \rfloor_q = -2$.

Both notations are used in similar contexts, such as modular arithmetic and cryptography, but they represent different things. In the context of the hidden number problem variant introduced by Boneh and Venkatesan, the notation $|n-r|_q$ is used to represent the difference between n and r taken mod q, while the notation $\lfloor x \rfloor_q$ is not used.

In summary, $|x|_q$ returns the unique representative of x in the set of integers mod q, while $\lfloor x \rfloor_q$ returns the greatest integer in the set of integers mod q that is less than or equal to x.