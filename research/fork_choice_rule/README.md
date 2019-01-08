Fork choice rule / Proof-of-stake

Specs implemented is Ghost LMD (Late-Message Driven Ghost)
Python research implementation: https://github.com/ethereum/research/tree/94ac4e2100a808a7097715003d8ad1964df4dbd9/clock_disparity

Mini-specs https://ethresear.ch/t/beacon-chain-casper-ffg-rpj-mini-spec/2760

(raw Markdown: https://ethresear.ch/raw/2760)

-------------------------

The purpose of this document is to give a "mini-spec" for the beacon chain mechanism for the purpose of security analysis, safety proofs and other academic reasoning, separate from relatively irrelevant implementation details.

### Beacon chain stage 1 (no justification, no dynasty changes)

Suppose there is a validator set $V = {V_1 ... V_n}$ (we assume for simplicity that all validators have an equal amount of "stake"), with subsets $S_1 .... S_{64}$ (no guarantee these subsets are disjoint, but we can guarantee $|S_i| \ge floor(\frac{|V|}{64})$), where $|x|$ refers to set size (ie. the number of validators, or whatever other kind of object, in $x$). Suppose also that the system generates a random permutation of validator indices, ${p_1 ... p_N}$.

> Note: if an attacker controls less than $\frac{1}{3}$ of the stake, then if $|S_i| \ge 892$ there is a less than $2^{-80}$ chance that the attacker controls more than $\frac{1}{2}$ of $S_i$, and there is a less than $2^{-100}$ chance that an attacker controls all 64 indices in a given span $i_k .... i_{k+63}$. We can assume that it is certain that neither of these things will happen (that is, we can assume there exists a substring of validator indices $p_{i_1}, p_{i_2} ...$ with $p_{i_{k+1}} - p_{i_k} < 64$ and that every $S_i$ is majority honest).

We divide time into **slots**; if the genesis timestamp of the system is $T_0$, then slot $i$ consists of the time period $[T_0 + 8i, T_0 + 8(i+1))$. When slot $i$ begins, validator $V_{p_{i\ mod\ N}}$ is expected to create ("propose") a block, which contains a pointer to some parent block that they perceive as the "head of the chain", and includes all of the **attestations** that they know about that have not yet been included into that chain. After 4 seconds, validators in $S_{i\ mod\ 64}$ are expected to take the newly published block (if it has actually been published) into account, determine what they think is the new "head of the chain" (if all is well, this will generally be the newly published block), and publish a (signed) attestation, $[current\_slot, h_1, h_2 .... h_{64}]$, where $h_1 ... h_{64}$ are the hashes of the ancestors of the head up to 64 slots (if a chain has missing slots between heights $a$ and $b$, then use the hash of the block at height $a$ for heights $a+1 .... b-1$), and $current\_slot$ is the current slot number.

The fork choice used is "latest message driven GHOST". The mechanism is as follows:

1. Set $H$ to equal the genesis block.
2. Let $M = [M_1 ... M_n]$ be the most-recent messages (ie. highest slot number messages) of each validator.
2. Choose the child of $H$ such that the subset of $M$ that attests to either that child or one of its descendants is largest; set $H$ to this child.
3. Repeat (2) until $H$ is a block with no descendants.

Claims:

* **Safety**: assuming the attacker controls less than $\frac{1}{3}$ of $V$, and selected the portion of $V$ to control before the validators were randomly sorted, the chain will never revert (ie. once a block is part of the canonical chain, it will be part of the canonical chain forever).
* **Incentive-compatibility**: assume that there is a reward for including attestations, and for one's attestation being included  in the chain (and this reward is higher if the attestation is included earlier). Proposing blocks and attesting to blocks correctly is incentive-compatible.
* **Randomness fairness**: in the long run, the attacker cannot gain by manipulating the randomness

### Beacon chain stage 2 (add justification and finalization)

As the chain receives attestations, it keeps track of the total set of validators that attest to each block. The chain keeps track of a variable, $last\_justified\_slot$, which starts at 0. If, for some block $B$ in the chain, a set of validators $V_B$ attest to it, with $|V_B| \ge |V| * \frac{2}{3}$, then $last\_justified\_slot$ is increased to the maximum of its previous value and that block's slot number. Attestations are required to state the $last\_justified\_slot$ in the chain they are attesting to to get included in the chain.

If a span of blocks (in the same chain) with slots $s$, $s+1$ ... $s+64$ (65 slots altogether) all get justified, then the block at slot $s$ is finalized.

We change the fork choice rule above so that instead of starting $H$ from the genesis block, it starts from the justified block with the highest slot number.

We then add two slashing conditions:

* A validator cannot make two distinct attestations in the same slot
* A validator cannot make two attestations with slot numbers $t1$, $t2$ and last justified slots $s1$, $s2$ such that $s1 < s2 < t2 < t1$

Claims:

* **Safety**: once a block becomes finalized, it will always be part of the canonical chain as seen by any node that has downloaded the chain up to the block and the evidence finalizing the block, unless at least a set of validators $V_A$ with $|V_A| \ge |V| * \frac{1}{3}$ violated one of the two slashing conditions (possibly a combination of the two).
* **Plausible liveness**: given an "honest" validator set $V_H$ with $|V_H| \ge |V| * \frac{2}{3}$, $V_H$ by itself can always finalize a new block without violating slashing conditions.

### Beacon chain stage 3: adding dynamic validator sets

Every block $B$ comes with a subset of validators $S_B$, with the following restrictions:

* Define the _dynasty_ of a block recursively: $dynasty(genesis) = 0$, generally $dynasty(B) = dynasty(parent(B))$ _except_ when (i) $B$'s 128th ancestor was finalized (and this fact is known based on what is included in the chain before B) and (ii) a dynasty transition has not taken place within the last 256 ancestors of $B$, in which case $dynasty(B) = dynasty(parent(B)) + 1$.
* Define the **local validator set** of $B$ as $LVS(B) = S_B \cup S_{parent(B)}\  \cup\ ... \ \cup\ S_{parent^{63}(B)}$
* Suppose for two blocks in the chain, $B_1$ and $B_2$, $dynasty(B_2) - dynasty(B_1) = k$. Then, $|LVS(B_1)\ \cap\ LVS(B_2)| \ge LVS(B_1) * (1 - \frac{k}{60})$ (and likewise wrt $LVS(B_2)$). That is, at most $\frac{1}{60}$ of the local validator set changes with each dynasty.

We modify the fork choice rule so that the seeking process reaches a block that includes a higher dynasty, it switches to using the latest messages from that dynasty.

Claims:

* All of the above claims hold, with appropriate replacements of $V$ with $LVS(...)$, except with fault tolerance possibly reduced from $\frac{1}{3}$ to 30\%.

