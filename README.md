# Núcleo

**A cryptographic integrity layer for software.** Núcleo lets any application seal its important records at the moment they happen — hashed, chained, signed, and encrypted — so that no later rewrite of the past is possible without leaving detectable, provable evidence.

Núcleo is **not** a blockchain, not a new database, and not a cloud service. It is a local, C2SP-compatible transparency log (`nucleod`, written in Go) plus thin client SDKs that sit **beside** the system you already have. It reconciles live data against sealed data, and issues signed receipts to interested parties that survive even if the original system is destroyed.

> *To anyone who tampers with a record, one question remains unanswerable: explain why the seal does not match.*

## Status

**Pre-alpha — protocol design frozen, core primitives implemented and tested.**

Working today:
- RFC 8785 (JCS) canonicalization, native implementation, official RFC test vectors passing
- Signed block headers (Ed25519 over SHA-256 digest), chain verification with expected-signer enforcement
- RFC 6962 Merkle tree with inclusion **and consistency** proofs (RFC 9162 §2.1.3 / §2.1.4), official vectors in `testdata/vectors/merkle/`
- Signed checkpoints (`c2sp.org/tlog-checkpoint`) over `x/mod/sumdb/note`
- Local witness with `c2sp.org/tlog-cosignature@v1`, refusing to cosign a rewritten history
- Offline-verifiable receipts (`c2sp.org/tlog-proof`) — no ledger access needed

```bash
go run ./cmd/nucleo-demo   # core: chain + Merkle + 3 tampering attacks
go run ./cmd/nucleo-poc    # C2SP end-to-end: checkpoint + witness + receipt + rewrite attack
```

## Benchmarks (PoC)

Measured 2026-09-04 on Go 1.27.1, linux/amd64, AMD Ryzen 7 5700U (16 threads).
Reproduce with `go test ./internal/ledger -bench=. -benchmem -run=XXX`.

| Measurement | Result |
|---|---|
| Block sealing (JCS + SHA-256 + Ed25519) | **20,983 blocks/s** — 47.7 µs/op, 5.6 KB, 92 allocs |
| Merkle root, 10³ leaves | 2.12 ms |
| Merkle root, 10⁵ leaves | 183 ms |
| **Receipt size**, 5-entry log | **485 bytes** (3 proof nodes) |
| **Receipt size**, 10³-entry log | **805 bytes** (10 proof nodes) |
| **Receipt size**, 10⁵-entry log | **1,124 bytes** (17 proof nodes) |

The receipt is what matters commercially: it grows logarithmically, so a log with
a hundred thousand entries still issues a self-contained, offline-verifiable
receipt of roughly one kilobyte — small enough for an email footer or a PDF
attachment. Root computation is not yet incremental; it recomputes the whole
tree, which is why 10⁵ leaves cost 183 ms. Caching subtree hashes is Sprint 2 work.

## Design

The full protocol and every design decision (with sources) live in:
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — normative protocol specification
- [`docs/adr/`](docs/adr/) — architecture decision records
- [`docs/CONCEPTO-v1.2-es.md`](docs/CONCEPTO-v1.2-es.md) — concept document (Spanish)

Key foundations: [C2SP](https://c2sp.org) (tlog-checkpoint, tlog-cosignature, tlog-witness, tlog-proof, tlog-tiles), RFC 6962/9162, RFC 8785, Ed25519 + ML-DSA-44, XChaCha20-Poly1305, Argon2id, SLIP-0039.

## Trust model (in one paragraph)

A locally sealed chain detects edits. Signed receipts (tlog-proof) held by counterparties survive destruction of the system. Mutual witnesses (any C2SP witness, including other Núcleo instances) cosign tree heads, making full-history rewrites detectable. Local timestamps are *declared time*; witness cosignature timestamps establish *provable time*. The ledger holds only non-guessable commitments; sensitive payloads live in erasable encrypted blobs (LOPDP/GDPR-friendly by construction).

## License

AGPL-3.0 for the core (see `LICENSE`). Commercial licenses are available for embedding Núcleo in proprietary software.
