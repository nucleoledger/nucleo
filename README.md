# Núcleo

**A cryptographic integrity layer for software.** Núcleo lets any application seal its important records at the moment they happen — hashed, chained, signed, and encrypted — so that no later rewrite of the past is possible without leaving detectable, provable evidence.

Núcleo is **not** a blockchain, not a new database, and not a cloud service. It is a local, C2SP-compatible transparency log plus thin client SDKs that sit **beside** the system you already have. It reconciles live data against sealed data, and issues signed receipts to interested parties that survive even if the original system is destroyed.

> *To anyone who tampers with a record, one question remains unanswerable: explain why the seal does not match.*

## Status

**v0.1.0-alpha — the success criterion runs end to end.**

The project defines its own bar in [`docs/CONCEPTO-v1.2-es.md`](docs/CONCEPTO-v1.2-es.md) §18: *a developer who knows no cryptography integrates Núcleo in under an hour, seals records, deliberately alters one, and reconciliation catches it and explains it.* That demo is automated and it passes:

```bash
./scripts/demo-criterio-exito.sh
```

Seven steps, thirty assertions, exit 0 or it fails loudly. It includes the cross-language check: a receipt produced by the Go implementation verifying byte-for-byte in the TypeScript verifier.

## Quick start

```bash
go build -o nucleo ./cmd/nucleo

./nucleo --dir ./my-company init --origin example.com/my-company
./nucleo --dir ./my-company seal --tenant 1790012345001 \
         --type invoice.v1 --payload ./invoice.xml
./nucleo --dir ./my-company status
```

The full walkthrough — including the witness, receipts and reconciliation — is [`docs/TUTORIAL-es.md`](docs/TUTORIAL-es.md) (Spanish; every command in it was executed and its output pasted verbatim).

## The CLI

One binary, no daemon, no external database. It runs per invocation so it works on the shared hosting where most of the target market lives.

| command | what it does |
|---|---|
| `init` | creates vault and ledger, prints SLIP-0039 backup cards, requires typed confirmation |
| `seal` | seals a record; `--profile` interprets the document and commits sensitive fields |
| `status` | tree size, root, and **whether the history is attested** |
| `verify` | integrity check; `--full` recomputes every signature |
| `receipt` | issues an offline-verifiable receipt for a recipient |
| `reconcile` | compares the live system against what was sealed |
| `sync` | obtains attestation from a witness |
| `witness serve` · `witness key` | runs a witness; prints its public key |
| `backup` · `restore` | re-issues the SLIP-0039 cards; rebuilds the KEK from them |

**Exit codes are contract** — scripts read them, so they will not change silently:

| code | meaning |
|---:|---|
| 0 | success |
| 1 | usage or input error |
| 2 | **verification failed** — an alteration or a discrepancy |
| 3 | **witness sync failed** — an operational incident if it repeats |

`--json` on any command produces machine output with no prose mixed in.

## What works today

**Core.** RFC 8785 (JCS) canonicalization with official vectors · signed block headers (Ed25519 over SHA-256) with chain verification · RFC 6962 Merkle tree with inclusion and consistency proofs (RFC 9162 §2.1.3/§2.1.4), official vectors · SQLite append-only store with integrity verification on open.

**C2SP.** Signed checkpoints (`tlog-checkpoint`) · witness cosignatures (`tlog-cosignature@v1`) · **the full HTTP witness protocol** (`tlog-witness`: `add-checkpoint` and the monitoring endpoint, with the spec version pinned in [ADR-011](docs/adr/ADR-011-witness-http.md)) · offline-verifiable receipts (`tlog-proof`).

**Keys and privacy.** Argon2id → KEK → per-vault DEK · XChaCha20-Poly1305 blobs with AAD bound to the commitment · **erasable payloads**: deleting a blob satisfies data-deletion rights while the chain and its receipts stay valid · SLIP-0039 backup with round-trip verification before the cards are ever shown · **ML-DSA-44 (FIPS 204) as an *additional* signature on the log's own checkpoint note**, carried in the `0xff` extension of `signed-note` under a Núcleo identifier ([ADR-007](docs/adr/ADR-007-mldsa44-adicional.md)). It is backward-compatible by construction — and that cuts both ways: a standard C2SP verifier ignores it. Witness cosignatures are still Ed25519. This is post-quantum hygiene on one signature, **not** a post-quantum chain end to end; see the limits below.

**Ecuador profile.** `sri.factura.v1` with módulo-11 access-key validation, and `sas.acta.v1`. Each type declares which fields are guessable and must travel as HMAC commitments rather than bare hashes.

**Verification anywhere.** [`@nucleoledger/verify`](sdk/ts) — a TypeScript verifier with **zero runtime dependencies** (Ed25519 and SHA-256 from WebCrypto) · [`web/verify/`](web/verify) — a single static HTML page that uses no network and verifies a receipt offline.

## Two clocks, never confused

A receipt shows both and labels them apart, because they are not the same thing:

- **Declared time** comes from the issuer's own clock. It can lie. It is shown because it is useful, not because it proves anything.
- **Provable time** is the earliest timestamp among witness cosignatures that verify under *your* policy. A third party stated it saw that tree at that moment.

With no accepted witness, the receipt says `SIN TIEMPO DEMOSTRABLE` in full. Staying silent and showing only the declared time would present it as proof.

## Benchmarks

Measured on Go 1.27.1, linux/amd64, AMD Ryzen 7 5700U (16 threads).
Reproduce with `go test ./internal/... -bench=. -run=XXX`.

| Measurement | Result |
|---|---|
| Block sealing (JCS + SHA-256 + Ed25519), in memory | **20,983 blocks/s** — 47.7 µs/op |
| Durable append (`synchronous=FULL`, one fsync each) | **826 blocks/s** |
| Open a 10⁵-block ledger, witness-attested | **412 ms** |
| Open a 10⁵-block ledger, no witness (verifies every signature) | 8.04 s |
| Merkle root, 10⁵ leaves | 195 ms |
| **Receipt size**, 5-entry log | **485 bytes** |
| **Receipt size**, 10⁵-entry log | **1,124 bytes** |

The receipt is what matters commercially: it grows logarithmically, so a log with a hundred thousand entries still issues a self-contained, offline-verifiable receipt of roughly one kilobyte — small enough for an email footer or a PDF attachment.

The durable rate, not the in-memory one, is what sizes a real deployment. Opening an attested ledger is 20× faster than opening an unattested one because signatures below a cosigned checkpoint are already attested; the trade-off is written down in the [ADR-009 amendment](docs/adr/ADR-009-store-schema.md).

## Trust model, in one paragraph

A locally sealed chain detects edits. Signed receipts held by counterparties survive destruction of the system. Witnesses cosign tree heads, which is what makes a full-history rewrite detectable — **a file cannot testify about its own completeness**, because whoever controls it controls any proof living inside it. Local timestamps are declared time; witness cosignature timestamps establish provable time. The ledger holds only commitments, never bare hashes of guessable values; sensitive payloads live in erasable encrypted blobs.

## Security & audits

This is a security product, so the process that built it is part of what you are trusting.

**Three independent models reviewed each other's work.** Each sprint's output was audited adversarially by a different model than the one that wrote it, with the reviewer given the primary specifications rather than the implementation's own claims. Every finding was resolved with a decision recorded in an ADR, never with a silent patch.

**Findings that were found and closed**, with the reasoning preserved:

| finding | severity | where it is recorded |
|---|---|---|
| Cosignature key ID used the wrong algorithm byte (0x01 instead of 0x04) | high | [PROTOCOL §3](docs/PROTOCOL.md), goldens computed with `sha256sum` |
| A file cannot detect its own truncation; `Open` reported success regardless | high | [ADR-009](docs/adr/ADR-009-store-schema.md) — `OpenResult.Attested` |
| The witness client accepted any well-formed cosignature, including from unknown keys | high | [ADR-011](docs/adr/ADR-011-witness-http.md) |
| A replayed but genuine old checkpoint silenced rollback detection | high | [ADR-011](docs/adr/ADR-011-witness-http.md) |
| AAD `tenant ‖ payload_hash` was ambiguous without a fixed-length suffix | medium | fixed-length `payload_hash` enforced |
| Provable time was computed from signature *shape*, not verified signatures | medium | verification now requires a policy |
| 422/409 status codes did not match `tlog-witness` | medium | [ADR-011](docs/adr/ADR-011-witness-http.md) |
| Test hooks were compiled into the production binary | high | [ADR-013](docs/adr/ADR-013-auditoria-pre-publica.md) |
| The Ecuador profile did not cross-check the access key against the XML | medium | [ADR-013](docs/adr/ADR-013-auditoria-pre-publica.md) |
| The TypeScript verifier truncated indices to 32 bits | medium | [ADR-013](docs/adr/ADR-013-auditoria-pre-publica.md) |
| A compiled `nucleo.exe` was committed to the tree — 17.6 MiB, 99% of the repo | high | removed; history left intact because the `v0.1.0-alpha` signature pins it |
| The witness `add-checkpoint` parser decoded base64 non-strictly, so two different request bodies produced the same request | medium | found by the new wire-format fuzzer; every other parser already used `.Strict()` |
| A receipt said nothing about what it is worth in front of a judge | medium | legal notice inside the receipt, covered by the byte-for-byte text check |
| The recipient line read as proof of delivery | medium | labelled in-line; the full fix is [ADR-015](docs/adr/ADR-015-destinatario.md), undecided |
| Stale attestation was nobody's incident: "nobody looks at `status`" | medium | fail-stale policy — `status`, `seal` and `verify` warn on stderr unprompted |
| Argon2id at 64 MiB × 4 lanes contradicts the shared-hosting target ADR-005 chose | medium | measured `--kdf-profile constrained`; the cost to an attacker is stated, not hidden |
| Process docs had drifted: PLAN.md still promised SQLite "next sprint" | low | PLAN/CLAUDE/AGENTS/TODO rewritten to the real state |

**Anti-circularity is a project rule.** Every golden value — hashes, key IDs, signatures, canonical bytes — is computed *outside* the code under test: `sha256sum`, `openssl`, an independent Python implementation, a C program linked against the reference Argon2 library. A test that verifies a function using that same function verifies nothing, and this project learned that the hard way.

**Limits we document rather than hide:**

- **"Attested" is only ever a *verified* claim, and verification needs a key from
  outside the file.** A stored checkpoint counts as attestation only if its log
  signature and its witness cosignatures verify under a policy you supply
  (`--witness-name`/`--witness-key`). Without it, `status` says "checkpoint present,
  NOT verified" and the fast open path is off. An adversarial audit fabricated a
  checkpoint that the old open path accepted on shape alone; the exploit is a
  regression test. ([ADR-016](docs/adr/ADR-016-atestacion-en-la-apertura.md))
- An adversary who **also controls the witness your policy accepts** can still have
  garbage cosigned: witnesses do not verify block signatures. `verify --full` catches
  it; a witness the issuer does not control is the real defense, and it is still
  product work. ([ADR-014](docs/adr/ADR-014-hoja-y-firma.md))
- The issuer's signature on a receipt proves who produced *this* document for *this*
  recipient. It does not prove delivery, and it does not stop the issuer from issuing
  another receipt for the same record to someone else.
  ([ADR-015](docs/adr/ADR-015-destinatario.md))
- A network adversary can prevent detection (availability, and it is noisy) but cannot forge attestation (integrity). ([ADR-011](docs/adr/ADR-011-witness-http.md))
- VRF commitments give third-party verifiability, **not** privacy: publishing a proof makes a low-entropy field brute-forceable. The ledger commitment is and stays HMAC. ([ADR-003](docs/adr/ADR-003-compromisos-vrf-hmac.md), [ADR-012](docs/adr/ADR-012-vrf-library.md))

**A fifth round came from outside the project**, after `v0.1.0-alpha` was published: a
model with no internal context, working only from what is public. Its most useful
findings were not cryptographic — they were about the product around the theorem: who
witnesses for a small business, how a PHP ERP seals in the same transaction, what the
receipt says in front of a judge, and what happens when somebody restores yesterday's
backup. Two of its findings became ADRs that are still **undecided**:
[ADR-014](docs/adr/ADR-014-hoja-y-firma.md) (put the block signature inside the Merkle
leaf) and [ADR-015](docs/adr/ADR-015-destinatario.md).

The full record of who audited what, across four rounds, is in
[ADR-013](docs/adr/ADR-013-auditoria-pre-publica.md).

**No external security audit has been performed.** The reviews above were model-driven and thorough, but they are not a substitute for a professional audit, and this software has not been used in production by anyone. Treat it accordingly.

To report a vulnerability privately, see [`SECURITY.md`](SECURITY.md).

## Design

The protocol and every design decision, with sources:

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — normative specification
- [`docs/adr/`](docs/adr/) — architecture decision records, including the amendments where a measurement contradicted an earlier assumption
- [`docs/TUTORIAL-es.md`](docs/TUTORIAL-es.md) — integration guide (Spanish)
- [`docs/RELEASING.md`](docs/RELEASING.md) — how releases are built, signed and verified
- [`docs/CONCEPTO-v1.2-es.md`](docs/CONCEPTO-v1.2-es.md) — concept document (Spanish)

Foundations: [C2SP](https://c2sp.org) (tlog-checkpoint, tlog-cosignature, tlog-witness, tlog-proof), RFC 6962/9162, RFC 8785, RFC 9381, Ed25519 (everywhere) + ML-DSA-44 (FIPS 204, one extra log signature), XChaCha20-Poly1305, Argon2id, SLIP-0039.

## Language

Core, protocol and technical documentation in **English**. Profiles, guides, receipts and user-facing output in **Spanish**, Ecuador first. That split is deliberate: the people who read a receipt are not the people who read a spec.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: issues are more useful than pull requests right now, `go test ./... -race` must stay green, and shared test vectors are ground truth — if a vector fails, the code is wrong, not the vector.

## License

AGPL-3.0-or-later for the core (see [`LICENSE`](LICENSE)). Commercial licenses are available for embedding Núcleo in proprietary software.
