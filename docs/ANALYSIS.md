# Analysis

The analysis crate measures the current profile and provides stable commands for regression testing.

## Decoder scan

```bash
cargo run --locked --release -p aperisyvra-analysis -- decoder-scan \
  --trials 10000 \
  --seed 7
```

The command generates one deterministic secret matrix, samples random weight-10 errors, and reports:

- trial count;
- decoder failures;
- average decoder rounds;
- maximum decoder rounds.

The seed controls both the secret matrix and the sampled error sequence. Results should be collected across many seeds rather than treated as a single global failure-rate estimate.

## Matrix report

```bash
cargo run --locked --release -p aperisyvra-analysis -- matrix-report \
  --secret alice.avsk
```

The report includes:

- minimum, maximum, and average secret row degree;
- maximum overlap between two secret columns;
- average public column weight;
- public matrix density.

The public-only report is available with:

```bash
cargo run --locked --release -p aperisyvra-analysis -- public-report \
  --public alice.avpk
```

## Current attack surface

### Generic syndrome decoding

P1 samples a weight-10 error among 256 coordinates. The raw subset count is approximately `2^57.95`. This is only a size indicator; practical information-set decoding and multi-target attacks require separate estimates.

### Sparse-matrix recovery

The secret matrix has low column weight and three row bands. Row mixing hides direct sparsity, but statistical or algebraic recovery of an equivalent sparse representation is the main structural question for P1.

Useful experiments include:

- low-weight combinations of public rows;
- public-column weight and correlation tests;
- short-cycle and spectrum comparisons against random matrices;
- classification of public keys by structure seed;
- recovery of the hidden row bands or coordinate permutation.

### Decoder failures

The two-pass bit-flip decoder is iterative and variable-time. Failure probability, selected pass, round count, and residual patterns may reveal information about the secret matrix. Measurements should cover many seeds and chosen error patterns.

### Message layer

The SHAKE256 stream and tag construction has not been independently analyzed as an authenticated-encryption scheme. Tampering tests are included for implementation correctness.

## Reproducibility

CI tests 16 deterministic secret matrices with 1,000 random weight-10 errors per matrix. It also runs key generation, message sealing, message opening, matrix reporting, unit tests, formatting, and Clippy. This is a regression suite, not a concrete security estimate.
