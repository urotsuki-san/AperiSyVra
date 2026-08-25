# Roadmap

## P1 hardening

- collect decoder failure data across many secret seeds;
- add chosen-error and trapping-set searches;
- export matrices for SageMath and external code-analysis tools;
- add low-weight row-combination searches;
- benchmark key generation and decapsulation on ARM64;
- protect secret-key files with an optional passphrase or OS key store;
- reduce secret-dependent timing in the decoder.

## Aperiodic structure

- replace the symbolic inflation schedule with a finite cut-and-project patch;
- encode Penrose matching constraints as parity checks;
- measure the contribution of hierarchy and orchard bands separately;
- test whether public keys reveal band membership or inflation lineage;
- compare decoder performance with random regular sparse matrices.

## Parameter work

- integrate current syndrome-decoding estimators;
- evaluate public-key size, decoder failure rate, and work factor together;
- define reduced profiles for exhaustive structural attacks;
- publish fixed test vectors before changing the binary format.

## Interface work

- add a small desktop key and message tool;
- add Android and iOS benchmark harnesses;
- add public-key cards and visual fingerprints shared with the SyVra design language;
- keep file encryption and mounted volumes in the OrIsyVra project.
