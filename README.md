# Núcleo

**A cryptographic integrity layer for software.** Núcleo lets any application seal its important records at the moment they happen — hashed, chained, signed, and encrypted — so that no later rewrite of the past is possible without leaving detectable, provable evidence.

Núcleo is **not** a blockchain, not a new database, and not a cloud service. It is a local, C2SP-compatible transparency log (`nucleod`, written in Go) plus thin client SDKs that sit **beside** the system you already have. It reconciles live data against sealed data, and issues signed receipts to interested parties that survive even if the original system is destroyed.

> *To anyone who tampers with a record, one question remains unanswerable: explain why the seal does not match.*

## Status

**Pre-alpha — protocol design frozen, core primitives implemented and tested.**

Working today (see `cmd/nucleo-demo`):
- RFC 8785 (JCS) canonicalization, native implementation, official RFC test vectors passing
- Signed block headers (Ed25519 over SHA-256 digest), chain verification with expected-signer enforcement
- RFC 6962 Merkle tree with inclusion proofs (RFC 9162 verification)
- Attack demo: edit, re-sign, and full-rewrite tampering detection

```bash
go run ./cmd/nucleo-demo
```

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
