# Translation of the spec in README.md

## Stage 1

### Part 1

> --------------------------------------
>
> Suppose there is a validator set $V = {V_1 ... V_n}$
> (we assume for simplicity that all validators have an equal amount > of "stake"),
> with subsets $S_1 .... S_{64}$
> (no guarantee these subsets are disjoint, but we can guarantee
> $|S_i| \ge floor(\frac{|V|}{64})$), where $|x|$ refers to set size
> (ie. the number of validators, or whatever other kind of object, > in $x$).
> Suppose also that the system generates a random permutation of > validator indices,
> ${p_1 ... p_N}$.
>
> --------------------------------------

In v2.1 specs terms

```
Validator        Vi => ValidatorRecord
Validators       V  => BeaconState.validators
Validator subset Si => ShardAndCommittee
```

### Part 2

> We divide time into **slots**; if the genesis timestamp of the system is $T_0$, then slot $i$ consists of the time period $[T_0 + 8i, T_0 + 8(i+1))$. When slot $i$ begins, validator $V_{p_{i\ mod\ N}}$ is expected to create ("propose") a block, which contains a pointer to some parent block that they perceive as the "head of the chain", and includes all of the **attestations** that they know about that have not yet been included into that chain. After 4 seconds, validators in $S_{i\ mod\ 64}$ are expected to take the newly published block (if it has actually been published) into account, determine what they think is the new "head of the chain" (if all is well, this will generally be the newly published block), and publish a (signed) attestation, $[current\_slot, h_1, h_2 .... h_{64}]$, where $h_1 ... h_{64}$ are the hashes of the ancestors of the head up to 64 slots (if a chain has missing slots between heights $a$ and $b$, then use the hash of the block at height $a$ for heights $a+1 .... b-1$), and $current\_slot$ is the current slot number.

In v2.1 specs terms

```
slot                      => BeaconBlock.slot
Validator Vpi mod N       => get_beacon_proposer(BeaconState, slot) -> ValidatorRecord
Proposed block            => ProposalSignedData (?)
Attestations              => AttestationRecord
Attestations not included => BeaconState.pending_attestations
Signed attestation        => AttestationSignedData
height                    => slot
```

### Part 3

> The fork choice used is "latest message driven GHOST". The mechanism is as follows:
>
> 1. Set $H$ to equal the genesis block.
> 2. Let $M = [M_1 ... M_n]$ be the most-recent messages (ie. highest slot number messages) of each validator.
> 2. Choose the child of $H$ such that the subset of $M$ that attests to either that child or one of its descendants is largest; set $H$ to this child.
> 3. Repeat (2) until $H$ is a block with no descendants.

In v2.1 specs terms

```
Current block H           => BeaconBlock / BeaconBlock.state_root / BeaconState.recent_block_hashes[^1] (?)
Messages                  => AttestationSignedData (?)
Child of H                => proc needed
```
