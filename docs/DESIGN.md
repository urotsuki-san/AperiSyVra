# AperiSyVra P1 Design

Profile: `AperiSyVra-AHC-N256/R192/W10-P1`

P1 is a binary syndrome KEM with a sparse secret parity-check matrix and a dense public representation. All integers in serialized files are little-endian.

## Parameters

| Symbol | Meaning | Value |
|---|---|---:|
| `N` | code coordinates | 256 |
| `R` | parity checks / syndrome bits | 192 |
| `W` | encapsulation error weight | 10 |
| `D` | secret column weight | 7 |
| `I` | decoder round limit per pass | 32 |

## Structure schedule

A 256-bit secret seed expands into one descriptor for each code coordinate.

Each descriptor contains:

- a symbol from the substitution `Thick → Thick Thin`, `Thin → Thick`;
- its inflation depth and lineage;
- one of five orientations;
- a primitive integer pair `(x, y)` with `gcd(x, y) = 1`;
- two consecutive values from an integer Fibonacci recurrence.

The descriptor is an input to SHAKE256 when the secret matrix rows are selected. It supplies deterministic variation across the local, hierarchy, and orchard bands.

## Secret matrix

The secret parity-check matrix has 192 rows and 256 columns. Rows are divided into three bands.

| Band | Rows | Checks per column |
|---|---:|---:|
| Local | 0–95 | 4 |
| Hierarchy | 96–159 | 2 |
| Orchard | 160–191 | 1 |

For each column, candidate rows are ranked by:

1. repeated-pair conflicts with rows already chosen for that column;
2. current row degree;
3. a descriptor-derived SHAKE256 score;
4. row number.

This keeps row degrees close and reduces four-cycles in the Tanner graph. Duplicate columns are rejected.

## Public-key transform

The seed also generates:

- 1,536 reversible row operations;
- a permutation of the 256 coordinates.

Row operations are bit swaps and `target ^= source`. Applied in reverse order, each operation is its own inverse.

Conceptually:

```text
H_public = R · H_secret · P
```

`R` makes the public columns dense. `P` hides the secret coordinate order. The secret key stores the seed and regenerates all derived material when needed.

## Encapsulation

The sender samples ten distinct public coordinates:

```text
e = {i0, i1, ..., i9}
```

The KEM ciphertext syndrome is:

```text
c = H_public[i0] XOR ... XOR H_public[i9]
```

The shared secret is the first 32 bytes of SHAKE256 over:

```text
public-key id || c || sorted public coordinates
```

## Decapsulation

The receiver:

1. regenerates the secret and public matrices from the secret seed;
2. applies the inverse row operations to the syndrome;
3. runs the bit-flip decoder on the secret matrix;
4. maps recovered secret coordinates back to public coordinates;
5. recomputes the public syndrome and public-key id;
6. derives the shared secret.

A failed decode or verification uses a deterministic fallback secret derived from the secret seed and ciphertext.

## Bit-flip decoder

P1 performs two deterministic passes from the original secret syndrome.

The first pass uses the threshold:

```text
max(4, largest unsatisfied-check score - 1)
```

If that pass does not produce a verified weight-10 error, the decoder restarts and uses the stricter threshold:

```text
max(4, largest unsatisfied-check score)
```

Within each pass, all coordinates at or above the threshold are flipped together and the residual syndrome is updated. A pass succeeds only when the residual becomes zero, exactly ten coordinates are set, and those coordinates reproduce the received public syndrome. Each pass is limited to 32 rounds.

## Message sealing

The sealed-message format carries one KEM ciphertext, a 24-byte nonce, a 32-byte tag, and the encrypted body.

The body is XORed with a SHAKE256 stream derived from:

```text
shared secret || public-key id || syndrome || nonce || length
```

The tag is SHAKE256 over:

```text
shared secret || message header || encrypted body
```

The current message size limit is 16 MiB.

## Implementation notes

- The core crate forbids `unsafe` code.
- Secret seeds and shared secrets are cleared on drop through `zeroize`.
- The public key and ciphertext parsers validate fixed parameters and key identifiers.
- Message plaintext is returned only after tag verification.
- The decoder is variable-time in P1.
