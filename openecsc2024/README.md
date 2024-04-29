# Invention

We are given [invention.sage](./invention.sage) and a connection to the server which is running it. The core of the program is the function `elliptic_hash`, which recieves a bytestring and returns two elliptic curve points.

The protocol for communicating with the server is as follows:

 - You send your username
 - The server sends you a random token
 - You send a password which has to start with said token
 - The server hashes your password and saves it
 - The server registers an admin user and you are shown the token and password of the admin
 - Finally we get to log in, in order to get the flag we must log in as our user (hence it has to start with our token), but the password hash must be that of the admin. Essentially we must find a hash collision for the admins password with a set prefix (our token).

## The algorithm

Let's look at how `elliptic_hash` is structured. Two different elliptic curves are used, $E$ and its quadratic twist $E^d$ which will be referred to as $T$. These two curves have the generators $G_E$ and $G_T$.

 We will not need any deep knowledge of elliptic curves to solve this, these are the main relevant principles: 

 - If the point $G$ is a generator of $E$ then any point on $E$ can be written as $kG$ for some integer $k$.

 - If a given $x$-coordinate does *not* correspond to a point on $E$ then it will correspond to a point on $T$, and vice versa.

When the program is initialized two random integers $0 < k_1 < |E|$ and $0 < k_2 < |T|$ are generated. These are then multiplied by the corresponding generator point of each curve to yield two new points $P_E = k_1 G_E$ and $P_T = k_2 G_T$ (`Pu` and `PTu` in the source code). We are shown $k_1$ and $k_2$ and can hence calculate both points ourselves.

The message is first divided up into blocks of 20 bytes, which corresponds to the size of the $x$-coordinate of a point on the curve. When referring to blocks from now on we are interested in their integer representation.

The first two blocks are special and will be denoted $a_E$ and $a_T$, the remaining blocks are $a_0, a_1, ...a_n$. The first step is to calculate $C_E = a_E P_E$ and $C_T = a_T P_T$ (`Ci` and `CTi` in the source code).

Afterwards, for each $a_i$, we check if its value corresponds to the $x$-coordinate of a point on $E$. If that is the case we lift the $x$-coordinate to the corresponding point, $A_i$, and add it to $C_E$ (i.e we modify $C_E$).

If the $x$-coordinate is not on $E$, and hence on $T$, it is lifted to a point $A_i$ on $T$ and added to $C_T$ instead.

The final hash is the tuple $(C_E, C_T)$, which will equal:

$$
(a_E P_E + \sum_{A_i \in E} A_i,\\
a_T P_T + \sum_{A_i \in T} A_i
)
$$

The final crux is that when we and the admin are first registering all the blocks we use are saved. Later, when logging in, we are only allowed to use blocks which were already used in the registration phase (from before we even know the admin's password).

## Collidin'

Since we are given the admin's password we can calculate the corresponding hash ourselves. The core problem is that we are forced to use the given token as our first block (i.e $a_E$).

Since the hash is split up into two parts ($C_E$ and $C_T$) let's first focus on the easier one: $C_T$. 

### $C_T$ - the easy part

Since we are given full control of $a_T$ we can simply set it to be the same as in the admin's password. From there we grab all blocks from the admin's password which are $\in T$ and add them to our password as well. Our $C_T$ will now be identitcal to the admin's. We are allowed to do this since the admin's blocks were added to the allowed ones during registration.

### $C_E$ - the hard part

Now for $C_E$. The $A_i \in E$ from the admin's password can be added to ours as well just as in the $C_T$ case, so we can ignore all but the first block.

Let's call $t$ our given token and $t_a$ the admin token. Before we even gain control $C_E$ will equal $t P_E = t k_1 G_E$. Recall that the result of the first admin block will be $t_a P_E= t_a k_1 G_E$. We thus want to find $A_i \in E$ such that $t k_1 G_E + \sum_{A_i \in E} A_i = t_a k_1 G_E$, or equivalently

$$
\sum_{A_i \in E} A_i = ((t_a-t)k_1)G_E
$$

If we rewrite each $A_i$ as some multiple of the generator $m_i G_E$ we get

$$
\sum_{A_i \in E} m_i G_E = ((t_a-t)k_1)G_E
$$

It thus suffices to find $m_i$ such that

$$
\sum_{A_i \in E} m_i \equiv (t_a-t)k_1 \pmod{|E|}
$$

This is a problem in integers which is a lot nicer to work with.

Normally we could just set $m_0 = (t_a-t)k_1$ and be done, but recall that we had the restriction that only blocks which had been used during registration may be used now, and when registering we don't know $t_a$ yet.

An important thing to note is that we may use one point several times by just repeating the block in the password, essentially multiplying the point by a small scalar. So if we predefine a set of points $(B_0, B_1, ..., B_n)$ during registration we can then build up any linear combination of them later, which will be of the form $\sum c_i B_i$ for reasonably small $c_i$ (otherwise the password will be too long).

There are several ways to choose a basis here. An easy approach would be to collect all powers of 2 times the generator, i.e $(G_E, 2G_E, 2^2G_E, ...)$. We could then build any multiple of $G_E$ by just looking at its binary representation. This will require as many points as there are bits in $|E|$.

### An annoying detail

A problem you will encounter is that due to implementation details in the source code our password is required to be valid utf-8, else the code will raise an error. You can get around this by for example brute-forcing pairs of points which sum to $2^kG_E$ and are each valid utf-8, but from my experience this takes a looong time.

We thus want to have as few basis points as possible since finding each one requires extensive brute force. My approach was to simply generate random multiples $m_i$ of $G_E$ and check if it decodes properly. I could then save the point together with that multiple, and after around 17 points I could reliably reach most points on the curve using quite small coefficients (in the base-2 case we restricted ourselves to coefficients of 0 and 1, we can now use any non-negative integer).

### Solving the instance

Finding the $c_i$ such that $\sum c_i m_i \equiv (t_a - t)k_1 \pmod{|E|}$ is not completely trivial. A common method is to use a lattice reduction algorithms like LLL, but configuring it such that all $c_i>0$ can be a bit cumbersome (although definitely possible). If you're interested the lattice will resemble the ones presented [here](https://mathweb.ucsd.edu/~crypto/Projects/JenniferBakker/Math187/).

I've encountered this problem several times before so I have made a utility which combines lattice reduction with some more exact linear programming methods. I was happy to be able to test it out so soon and it worked well for this purpose, you can check it out [here](https://github.com/TheBlupper/linineq).

## Conclusion

This covers all the ideas used in [my solve script](./solve.py), read it for more details. This was a very fun challenge which combined several known primitives into an interesting problem, thanks to the author for writing it and I hope we will see more like this in the ECSC finals! 🇮🇹🤌🍕🍍