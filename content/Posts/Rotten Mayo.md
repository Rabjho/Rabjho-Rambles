---
type: post
publish: true
title: Rotten Mayo
created: 2026-05-10T00:00:00.000Z
author:
  - Rabjho
ctf: DDC2026
role: author
tags:
  - crypto
  - author
---
Post-quantum crypto challenge exploiting a subtle implementation bug in the MAYO signature scheme.

## Rotten Mayo

> Restauranten hvor jeg arbejder, har ikke den bedste hygiejne. Kan du hjælpe mig med at finde ud af, hvad der er galt med vores MAYO? Jeg tror ikke, den er helt sikker at spise.

> Author: dfaranha, Rabjho (me)
>
> Category: crypto

The challenge runs a server that signs a known message with the MAYO post-quantum signature scheme, gives you both the public key and a signature, and then asks you to forge a signature on a different message. To understand the exploit, we first need to understand what MAYO actually is.

### What is MAYO?

[MAYO](https://pqmayo.org/) is a post-quantum digital signature scheme currently in NIST's standardization process. It's built on top of a much older idea called [**Oil and Vinegar (OV)**](https://en.wikipedia.org/wiki/Unbalanced_oil_and_vinegar_scheme), so let's start there.

#### Oil and Vinegar in a nutshell

Imagine you have $n$ variables split into two groups: $n_v$ **vinegar** variables and $o$ **oil** variables (where $n = n_v + o$). The public key is a set of $m$ multivariate quadratic polynomials $P : \mathbb{F}_q^n \to \mathbb{F}_q^m$. The secret is a hidden $o$-dimensional subspace $O \subset \mathbb{F}_q^n$ - the "oil space" - on which $P$ vanishes: $P(o) = 0$ for all $o \in O$.

Why is this useful? Because quadratic polynomials have a nice property: for any quadratic map $P$, we can define its **differential** $P'(x, y) = P(x + y) - P(x) - P(y)$, which is bilinear (linear in each argument separately). Now look at what happens when we try to find $s$ such that $P(s) = t$. We write $s = v + o$ where $v$ is a random "vinegar" vector and $o \in O$ is an oil vector. Expanding:

$$P(v + o) = P(v) + P(o) + P'(v, o) = t$$

Since $P$ vanishes on $O$, the $P(o)$ term disappears. And $P'(v, o)$ is *linear* in $o$ (since $P'$ is bilinear and $v$ is fixed). So we're left with:

$$P'(v, o) = t - P(v)$$

This is a system of $m$ linear equations in $o$ oil variables. As long as $o \geq m$ (i.e., there are at least as many oil variables as equations), this system almost always has a solution. The signer picks a random $v$, solves for $o$, and outputs $s = v + o$.

To **verify**, anyone can just check that $P(s) = t$. The security rests on the fact that recovering the oil space $O$ from the public map $P$ is hard.

The catch with plain OV is that the public key - $m$ quadratic polynomials in $n$ variables - is enormous ($\sim 50$ KB for reasonable security). That's where MAYO comes in.

#### The MAYO twist: whipping

MAYO shrinks the oil space to be much smaller than in standard OV (i.e., $o \ll m$). This makes the public key far more compact (fewer oil variables means fewer coefficients to store), but now you can't sign anymore: the linear system $P'(v, o) = t - P(v)$ has $o < m$ unknowns and $m$ equations, so it's overdetermined and usually has no solution.

The fix is to "whip" the map. MAYO takes the base map $P$ and constructs a larger map $P^*$ that takes $k$ input vectors instead of one:

$$P^*(x_1, \ldots, x_k) = \sum_{i=1}^{k} P(x_i) + \sum_{i < j} E_{ij} \cdot P'(x_i, x_j)$$

where the $E_{ij} \in \mathbb{F}_q^{m \times m}$ are fixed public matrices. The key property: if $P$ vanishes on the oil space $O$, then $P^*$ vanishes on $O^k = \{(o_1, \ldots, o_k) \mid o_i \in O\}$. This is because each $P(o_i) = 0$ and $P'(o_i, o_j) = 0$ when both arguments are in $O$ (since $P'$ is the differential of a map that vanishes on $O$).

The oil space of $P^*$ is $O^k$, which has dimension $ko$. By choosing $k$ such that $ko > m$, the signer has enough unknowns to solve the linear system again. In the representation used by the implementation, oil vectors are expressed relative to a secret basis. The secret key is a matrix $\hat{O}$ of size $n_v \times o$ that maps oil coefficients into the vinegar coordinate space. Each signature block $s_i$ is constructed as:

$$s_i = v_i + \hat{O} \cdot x_i$$

where $v_i \in \mathbb{F}_q^{n_v}$ is a random vinegar vector and $x_i \in \mathbb{F}_q^o$ are the oil coefficients found by solving the linear system. The first $n_v$ coordinates of $s_i$ are the vinegar part (which includes $v_i$ plus the oil contribution $\hat{O} \cdot x_i$), and the last $o$ coordinates are simply $x_i$. A full signature is the tuple $s = (s_1, \ldots, s_k)$.

### What does `main.sage` do?

The server:

1. Generates a MAYO keypair (compact secret key `csk`, compact public key `cpk`).
2. Signs a fixed message `b"This is a message to sign"` and sends you the public key and the full raw signature (all $k$ signature blocks, not just the compressed output).
3. Asks you to forge a signature on `b"Give me the flag!"`.
4. Verifies your forgery and, if valid, prints the flag.

### Diff with [original `mayo.sage`](https://github.com/PQCMayo/MAYO-sage/blob/main/mayo.sage#L272)

```diff
272c272
<                     V[i*self.v_bytes:(i+1)*self.v_bytes], self.n-self.o)
---
>                     V[0:self.v_bytes], self.n-self.o)
```

A single-line change. In the signing function, the vinegar values for each of the $k$ signature blocks are supposed to be derived from different slices of the random seed `V`. The bug reuses the *same* slice `V[0:self.v_bytes]` for every block $i$. This means that all $k$ blocks share the **same vinegar vector** $v$.

### Enumerating the problem

Before diving into the full exploit, let's confirm the bug is real and understand what it leaks. Recall that each signature block $s_i$ is an $n$-dimensional vector over $\mathbb{F}_q$. The first $n_v$ coordinates are the vinegar part, and the last $o$ coordinates are the oil coefficients $x_i$. Block $i$ has the form:

$$s_i = \begin{pmatrix} v + \hat{O} \cdot x_i \\ x_i \end{pmatrix}$$

where $v$ is the (now identical) vinegar part and $x_i \in \mathbb{F}_q^o$ is the oil coefficient vector for block $i$. If we subtract any two blocks:

$$s_i - s_j = \begin{pmatrix} \hat{O} \cdot (x_i - x_j) \\ x_i - x_j \end{pmatrix}$$

The vinegar cancels out completely. Writing $\Delta x = x_i - x_j$ and $\Delta s = s_i[:n_v] - s_j[:n_v]$ for the vinegar-coordinate difference, we get:

$$\Delta s = \hat{O} \cdot \Delta x$$

This is a direct linear equation in the entries of the secret matrix $\hat{O}$. And we know *both sides*: $\Delta x$ is just the difference of the oil coordinates (readable from the last $o$ entries of each block), and $\Delta s$ is the difference of the vinegar coordinates (the first $n_v$ entries).

We can verify this by connecting to the server, parsing the signature, and checking that the differences between blocks are consistent with a shared vinegar vector. Here's a quick enumeration script:

```python
#!/usr/bin/env python3
from pwn import remote
from sage.all import *

# Load the MAYO implementation (compiled from mayo.sage)
with open("/app/mayo.sage.py") as _f:
    exec(compile(_f.read(), "/app/mayo.sage.py", "exec"), globals())

mayo = Mayo(DEFAULT_PARAMETERS["mayo_3"])
F16 = GF(16, "x")
nv = mayo.n - mayo.o
full_sig_bytes = mayo.k * mayo.n * 4 // 8
msg = b"This is a message to sign"

with remote("127.0.0.1", 1337) as rem:
    cpk = bytes.fromhex(rem.readline().decode("utf-8"))
    raw_sig = bytes.fromhex(rem.readline().decode("utf-8"))

    # Decode the k signature blocks
    sv_full = decode_vec(raw_sig[:full_sig_bytes], mayo.k * mayo.n)
    sv = [sv_full[i * mayo.n : (i + 1) * mayo.n] for i in range(mayo.k)]

    # Compare each block against block 0
    s0_vin = sv[0][:nv]
    x0 = sv[0][nv:]

    for i in range(1, mayo.k):
        delta_s = s0_vin - sv[i][:nv]   # vinegar-coordinate difference
        delta_x = x0 - sv[i][nv:]       # oil-coordinate difference
        print(f"Block 0 vs {i}:")
        print(f"  delta_x zero? {delta_x.is_zero()}")
        print(f"  delta_s zero? {delta_s.is_zero()}")

        # If the bug is present, delta_s should equal O_hat * delta_x.
        # We can't verify that directly yet, but we CAN check that the
        # vinegar differences all lie in the same subspace:
        if not delta_x.is_zero():
            print(f"  -> Got a nontrivial equation for O_hat recovery")
```

Output:

```
Block 0 vs 1:
  delta_x zero? False
  delta_s zero? False
  -> Got a nontrivial equation for O_hat recovery
Block 0 vs 2:
  delta_x zero? False
  delta_s zero? False
  -> Got a nontrivial equation for O_hat recovery
...
Block 0 vs 10:
  delta_x zero? False
  delta_s zero? False
  -> Got a nontrivial equation for O_hat recovery
```

Every block pair yields a nontrivial equation - exactly what we'd expect from the vinegar reuse bug.

If the vinegar values were truly independent (as in the correct implementation), these differences would look random - there'd be no consistent linear relation between $\Delta s$ and $\Delta x$. With the bug, every pair gives us an equation $\Delta s = \hat{O} \cdot \Delta x$, and after collecting $o$ linearly independent such equations, we can solve for $\hat{O}$ exactly.

### Exploit

With the bug confirmed, the attack proceeds in three stages.

**Step 1: Recover $\hat{O}$**

From the $k$ signature blocks we get $k - 1$ equations of the form $\Delta s = \hat{O} \cdot \Delta x$. Let's write this out more explicitly. $\hat{O}$ is an $n_v \times o$ matrix, so each equation $\Delta s^{(j)} = \hat{O} \cdot \Delta x^{(j)}$ is really $n_v$ scalar equations - one for each vinegar coordinate. For the $\ell$-th vinegar coordinate:

$$\Delta s^{(j)}_\ell = \sum_{c=1}^{o} \hat{O}_{\ell, c} \cdot \Delta x^{(j)}_c$$

If we collect enough pairs (at least $o$ with linearly independent $\Delta x$ vectors), we can stack them into a matrix equation. Let $X$ be the matrix whose rows are the $\Delta x^{(j)}$ vectors and $R$ be the matrix whose rows are the $\Delta s^{(j)}$ vectors. Then:

$$R = X \cdot \hat{O}^T$$

or equivalently, for each vinegar coordinate $\ell$, the $\ell$-th column of $R$ equals $X$ times the $\ell$-th row of $\hat{O}$ (transposed). So we solve $o$ independent linear systems - one per vinegar coordinate:

$$X \cdot \hat{O}_\ell^T = R_\ell \quad \text{for } \ell = 1, \ldots, n_v$$

This requires $\text{rank}(X) \geq o$, i.e., we need at least $o$ linearly independent $\Delta x$ vectors. We get $k - 1$ equations per signature, and for `mayo_3` parameters $k$ might be smaller than $o$, so the solver reconnects until it has enough:

```python
X_rows = []   # delta_x vectors (GF(16)^o)
R_rows = []   # delta_s vectors (GF(16)^nv)

s0_vin = sv[0][:nv]
x0 = sv[0][nv:]

for j in range(1, mayo.k):
    delta_x = x0 - sv[j][nv:]
    delta_s = s0_vin - sv[j][:nv]
    if not delta_x.is_zero():
        X_rows.append(delta_x)
        R_rows.append(delta_s)
```

If $k - 1 \geq o$ and the $\Delta x$ vectors are linearly independent, we can solve directly. For `mayo_3` parameters this might not hold from a single signature (since $k$ might be smaller than $o$), so the solver reconnects until it collects enough independent rows:

```python
if len(X_rows) >= mayo.o and matrix(F16, X_rows).rank() >= mayo.o:
    X = matrix(F16, X_rows)
    R = matrix(F16, R_rows)

    O_hat = matrix(F16, nv, mayo.o)
    for j in range(nv):
        O_hat[j] = X.solve_right(R.column(j))
```

The loop over `j` is exactly the column-by-column solve described above: for each vinegar coordinate $j$, we solve $X \cdot \hat{O}_j^T = R_j$.

**Step 2: Reconstruct a usable secret key**

With $\hat{O}$ recovered, we can reconstruct the expanded secret key. The MAYO expanded secret key contains three parts: $\hat{O}$ itself, the public matrices $P_1$ (the quadratic forms restricted to vinegar-vinegar interactions), and the $L$ matrices used to speed up signing.

The $L$ matrices come from precomputing part of the linear system that arises during signing. Recall that signing requires evaluating $P'(v, o)$, the differential of $P$ applied to a vinegar vector $v$ and an oil vector $o$. Each quadratic form $P_i$ can be written as a matrix: $P_i(x) = x^T M_i x$ for some upper-triangular matrix $M_i$. The differential is $P_i'(v, o) = v^T (M_i + M_i^T) o$. Since the oil vector is $o = \hat{O} \cdot x$ (in vinegar coordinates), we get:

$$P_i'(v, \hat{O} \cdot x) = v^T (M_i + M_i^T) \hat{O} \cdot x$$

The part $(M_i + M_i^T) \hat{O}$ doesn't depend on $v$ or $x$, so it can be precomputed. But $M_i$ has a block structure: its vinegar-vinegar block is $P_{1,i}$ and its vinegar-oil block is $P_{2,i}$. The relevant precomputation yields:

$$L_i = (P_{1,i} + P_{1,i}^T) \cdot \hat{O} + P_{2,i}$$

The public key seed lets us re-derive $P_1$ and $P_2$ (they're deterministically expanded from a seed), so with $\hat{O}$ in hand we can compute $L$ directly. We don't need the original secret seed - any random seed works for the `seed_sk` field, since the signing algorithm only uses $\hat{O}$, $P_1$, and $L$:

```python
o_bytestring = encode_vec(
    vector(F16, [O_hat[i, j] for i in range(nv) for j in range(mayo.o)])
)

# Re-derive P1, P2 from the public seed
seed_pk = cpk[:mayo.pk_seed_bytes]
ctr_gen = AES128_CTR(seed_pk, mayo.P1_bytes + mayo.P2_bytes)
p_bytes = ctr_gen.aes_ctr_gen()

p1 = decode_matrices(p_bytes[:mayo.P1_bytes], mayo.m, nv, nv, triangular=True)
p2 = decode_matrices(
    p_bytes[mayo.P1_bytes:mayo.P1_bytes + mayo.P2_bytes],
    mayo.m, nv, mayo.o, triangular=False,
)

# Compute L matrices
l = [matrix(F16, nv, mayo.o) for _ in range(mayo.m)]
for i in range(mayo.m):
    l[i] = (p1[i] + p1[i].transpose()) * O_hat + p2[i]

# Pack into a fake expanded secret key
fake_seed_sk = os.urandom(mayo.sk_seed_bytes)
fake_esk = (
    fake_seed_sk
    + o_bytestring
    + p_bytes[:mayo.P1_bytes]
    + encode_matrices(l, mayo.m, nv, mayo.o, triangular=False)
)
```

**Step 3: Forge**

With a valid expanded secret key, we just call `mayo.sign()` on the target message and send it back:

```python
TARGET = b"Give me the flag!"
raw = mayo.sign(TARGET, fake_esk)
sig_bytes = raw[:mayo.sig_bytes]

assert mayo.verify(sig_bytes, TARGET, epk)  # sanity check locally
conn.sendline(sig_bytes.hex())
# flag!
```

The server verifies, and out comes the flag.

### Full solve script

Solve script by dfaranha:

```python
#!/usr/bin/env python3
from pwn import remote
import base64
import json
import os as _os
from sage.all import *

with open("/app/mayo.sage.py") as _f:
    exec(compile(_f.read(), "/app/mayo.sage.py", "exec"), globals())

HOST = _os.environ.get("HOST", "localhost")
PORT = _os.environ.get("PORT", "1337")

mayo = Mayo(DEFAULT_PARAMETERS["mayo_3"])
F16 = GF(16, "x")

# Step 1: recover O_hat

msg = b"This is a message to sign"
full_sig_bytes = mayo.k * mayo.n * 4 // 8

while True:
	X_rows = []  # delta_x vectors in GF(16)^o
	R_rows = []  # delta_s vectors in GF(16)^nv
	with remote("127.0.0.1", 1337) as rem:
		nv = mayo.n - mayo.o
		cpk = bytes.fromhex(rem.readline().decode("utf-8"))
		epk = mayo.expand_pk(cpk)
		print("[*] Got public key")
		raw_sig = bytes.fromhex(rem.readline().decode("utf-8"))
		salt = raw_sig[full_sig_bytes : full_sig_bytes + mayo.salt_bytes]
		sv_full = decode_vec(raw_sig[:full_sig_bytes], mayo.k * mayo.n)
		sv = [sv_full[i * mayo.n : (i + 1) * mayo.n] for i in range(mayo.k)]

		# Reference block 0
		s0_vin = sv[0][:nv]
		x0 = sv[0][nv:]

		for j in range(1, mayo.k):
			sj_vin = sv[j][:nv]
			xj = sv[j][nv:]

			delta_x = x0 - xj  # GF(16)^o
			delta_s = s0_vin - sj_vin  # GF(16)^nv = O_hat * delta_x

			# Skip if delta_x is zero (unlikely but possible)
			if delta_x.is_zero():
				continue

			X_rows.append(delta_x)
			R_rows.append(delta_s)

		if len(X_rows) >= mayo.o and matrix(F16, X_rows).rank() >= mayo.o:
			X = matrix(F16, X_rows)  # shape: samples x o
			R = matrix(F16, R_rows)  # shape: samples x nv

			O_hat = matrix(F16, nv, mayo.o)
			for j in range(nv):
				O_hat[j] = X.solve_right(R.column(j))

			print(f"[+] O_hat recovered ({nv}x{mayo.o})")

			# Step 2: reconstruct esk

			o_bytestring = encode_vec(
				vector(F16, [O_hat[i, j] for i in range(nv) for j in range(mayo.o)])
			)

			seed_pk = cpk[: mayo.pk_seed_bytes]
			ctr_gen = AES128_CTR(seed_pk, mayo.P1_bytes + mayo.P2_bytes)
			p_bytes = ctr_gen.aes_ctr_gen()

			p1 = decode_matrices(p_bytes[: mayo.P1_bytes], mayo.m, nv, nv, triangular=True)
			p2 = decode_matrices(
				p_bytes[mayo.P1_bytes : mayo.P1_bytes + mayo.P2_bytes],
				mayo.m,
				nv,
				mayo.o,
				triangular=False,
			)

			l = [matrix(F16, nv, mayo.o) for _ in range(mayo.m)]
			for i in range(mayo.m):
				l[i] = (p1[i] + p1[i].transpose()) * O_hat + p2[i]

			fake_seed_sk = _os.urandom(mayo.sk_seed_bytes)
			fake_esk = (
				fake_seed_sk
				+ o_bytestring
				+ p_bytes[: mayo.P1_bytes]
				+ encode_matrices(l, mayo.m, nv, mayo.o, triangular=False)
			)

			# Step 3: forge
			TARGET = b"Give me the flag!"
			raw = mayo.sign(TARGET, fake_esk)
			sig_bytes = raw[: mayo.sig_bytes]

			assert(mayo.verify(sig_bytes, TARGET, epk))
			print("[+] Forgery verified locally")
			rem.sendline(sig_bytes.hex())
			print(rem.recvuntil("}"))
			rem.interactive()
			exit(0)
```

### Tl;Dr

1. MAYO is a post-quantum signature scheme based on Oil and Vinegar. The secret key is a hidden linear subspace (the "oil space"), and signing works by solving a linear system using this trapdoor.
2. The challenge introduces a one-line bug: all $k$ signature blocks reuse the same vinegar vector instead of independent ones.
3. This lets us subtract pairs of blocks to cancel out the vinegar, revealing linear equations in the secret matrix $\hat{O}$.
4. With enough equations we recover $\hat{O}$, reconstruct a working secret key, forge a signature on the target message, and get the flag.
