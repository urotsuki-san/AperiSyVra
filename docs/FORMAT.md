# Binary Formats

All integers are little-endian. P1 uses fixed parameter values; parsers reject other values.

## Public key (`.avpk`)

Total size: 6,176 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `AVPKP1\0\0` |
| 8 | 2 | format version (`1`) |
| 10 | 2 | code length (`256`) |
| 12 | 2 | syndrome bits (`192`) |
| 14 | 1 | error weight (`10`) |
| 15 | 1 | secret column weight (`7`) |
| 16 | 16 | public-key id |
| 32 | 6,144 | 256 public columns, 24 bytes each |

The public-key id is derived from the parameters and all public columns.

## Secret key (`.avsk`)

Total size: 44 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `AVSKP1\0\0` |
| 8 | 2 | format version (`1`) |
| 10 | 2 | reserved (`0`) |
| 12 | 32 | secret seed |

The current CLI stores this file without password protection.

## KEM ciphertext (`.avct`)

Total size: 52 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `AVCTP1\0\0` |
| 8 | 2 | format version (`1`) |
| 10 | 2 | reserved (`0`) |
| 12 | 16 | recipient public-key id |
| 28 | 24 | syndrome |

## Sealed message (`.avm`)

Header size: 116 bytes.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `AVMSG1\0\0` |
| 8 | 2 | format version (`1`) |
| 10 | 2 | flags (`0`) |
| 12 | 16 | recipient public-key id |
| 28 | 24 | KEM syndrome |
| 52 | 24 | message nonce |
| 76 | 8 | plaintext length |
| 84 | 32 | authentication tag |
| 116 | variable | encrypted body |

The encoded length must equal `116 + plaintext length`. P1 accepts messages up to 16 MiB.
