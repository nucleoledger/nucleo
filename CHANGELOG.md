# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the on-disk format and the wire formats may
change between minor versions. What will **not** change silently: the CLI exit
codes, and any golden test vector in `testdata/vectors/`.

## [Unreleased]

### ⚠ Breaking: the Merkle leaf and the receipt format changed (PROTOCOL 0.2-draft)

**Every root, checkpoint and receipt produced before this release is incompatible, and
there is no migration path because there is nobody to migrate: `v0.1.0-alpha` shipped
one day earlier with no known deployments and no third-party receipts.**

Two accepted ADRs, implemented together on purpose so the break happens once:

- **[ADR-014](docs/adr/ADR-014-hoja-y-firma.md) — `leaf/v2`.** A Merkle leaf is now
  `hash ‖ signature` (32+64 raw bytes, no separator: both fields are fixed length) and
  not the block hash alone. Under `leaf/v1` a cosigned root said nothing about the
  `signature` column, so an adversary with write access could garble every signature
  and the fast open path still reported the history as attested. `verify --full` caught
  it, and as the external review put it: "`verify --full` is not mitigation if nobody
  runs it". Now the check that already happens on open covers the signatures, with no
  extra Ed25519 verification — what detects the tampering is the tree.

  The residual gap is documented and has its own test: `leaf/v2` guarantees the
  signature *bytes* are the ones present when the root was cosigned, not that they were
  a valid signature. A dishonest issuer can write garbage, compute the root over it and
  have a witness cosign that — witnesses do not verify block signatures, it is not
  their job and they do not hold the keys. `verify --full` remains the route that
  catches it, naming the block.

- **[ADR-015](docs/adr/ADR-015-destinatario.md) — the issuer signs the receipt.** The
  issuer's Ed25519 signature now covers the **whole receipt**, recipient included, so
  rewriting the recipient invalidates the document. The label
  `(anotado por el emisor, no firmado)` is replaced by `(firmado por el emisor)`.

  This only became cheap *because* ADR-014 landed first: the verifying key is
  `header.signer_pubkey`, the header is inside the leaf, and the leaf is under a root
  witnesses cosign — so **a counterparty verifies with nothing but the receipt and its
  policy. No key directory, no out-of-band exchange, no new PKI.** What the signature
  does not establish, stated wherever it is shown: delivery, or that the issuer did not
  issue another receipt for the same record to somebody else.

**The leaf rule is now a first-class, versioned concept** (PROTOCOL §2.1), which is the
part meant to outlive this change: a log records its rule at creation and refuses to
open under a different one; the receipt magic carries it (`@v1` → `@v2`); a segment may
never contain two rules, and a future migration closes the current segment and opens
the next one under the new rule (ADR-006), chained by RFC 9162 §2.1.4 consistency
proofs. That route did not exist for v1→v2, which is precisely what made this change a
one-time opportunity rather than routine maintenance.

Practical consequences for anyone who had a working setup:

- `nucleo receipt` now asks for the passphrase, because it signs.
- A receipt is ~220 bytes larger (4740 → 4962 in the tutorial's example).
- A `@v1` receipt is recognised and rejected with a message that says so, in Go, in
  TypeScript and on the static page — not with a confusing error about a missing field.
- `status` publishes `leaf_rule`, and the RFC 6962 vectors are untouched: they test the
  tree algorithm with arbitrary leaf data, and `merkle.go` did not change.

### Receipts

- Receipts carry a **legal notice in Spanish**, inside the human-readable text and
  therefore covered by the byte-for-byte equality that `Parse` enforces: a receipt
  with the notice stripped or softened no longer verifies. It says what the document
  is (technical evidence of integrity and time) and what it is not (a public act, a
  notarial certification, a ruling by any authority), and that its evidentiary weight
  is for an expert witness or a judge to determine. The static verifier shows the same
  wording, with its own style rather than grey fine print.
- The recipient line now carries the label **"(anotado por el emisor, no firmado)"**,
  on the same line as the name so a careless copy-paste cannot separate them. The
  verifier returns the clean name; the static page re-adds the label. Issuing a receipt
  whose recipient *contains* that label is refused, because it would print the label
  twice and ambiguity on that line is the thing the label removes. The full option —the
  issuer signing the whole receipt— is evaluated in
  [ADR-015](docs/adr/ADR-015-destinatario.md) and **not implemented**: without a
  published issuer key it would be a signature nobody can check.

### Operation

- **Fail-stale policy.** `status`, `seal` and `verify` warn on **stderr** — in `--json`
  mode too, where the verdict is also in the `freshness` object — when the last
  *verified* attestation is older than a configurable threshold (`--stale-after`,
  72h by default), or when there has never been one. None of the three fails because
  of it: integrity and freshness are different questions, and `sync` is the command
  that exits 3 when it genuinely could not do its job.

  The comparison uses the timestamp **the witness asserted** in its cosignature, read
  only after verifying it against the witness key — not the local clock, which is the
  clock someone would move to keep the alarm quiet. A clock so far off that the
  attestation looks like it came from the future is reported as skew rather than
  silently treated as fresh.

  stderr is the point: a cron line that sends stdout to a file sends stderr to the
  administrator's mail, so the alarm rings without anyone having to wire it up. The
  failure mode this addresses is not an attack — it is a cron job that quietly stopped
  running, which nothing in the system used to notice.
- **`init --kdf-profile {default,constrained}`**, measured rather than guessed. The
  default (t=3, p=4, m=64 MiB) is exactly RFC 9106 §4's second recommended option;
  `constrained` (t=2, p=1, m=19 MiB) is the OWASP Password Storage minimum — below a
  standards recommendation, and labelled as such in the CLI's own output. On a Ryzen 7
  5700U, unlocking costs **51 ms / 67 MB** against **25 ms / 20 MB**; with 8 GiB an
  attacker goes from ~2,400 to ~16,700 guesses per second, a factor of **7**.

  It exists because ADR-005 chose a CLI precisely for shared hosting, where 64 MiB × 4
  lanes is what LVE/CageFS kills first — so the real alternative to the weaker profile
  is not a stronger one, it is no encryption at all. Parameters are stored in the vault
  and `Unlock` uses the stored ones, with a test that proves it by substituting them and
  requiring the unlock to fail.

### Testing

- **Fuzzers for every wire format**, not just JCS: the checkpoint body, the signed note
  (parse and verify paths), the `tlog-cosignature@v1` signature blob, the `tlog-proof`
  receipt, the full receipt with its human-readable wrapper, and the body of the witness
  `add-checkpoint` request — the one that arrives over HTTP from anyone who can reach
  the port, before anything is verified.

  Two invariants, and the second is the one that found something: no panic, and **a
  rejection leaves no half-state** — when a parser returns an error, the value it
  returns must be the zero value. A parser that fills in half a struct *and* returns an
  error invites the caller to use that half.

  The accepted inputs are also required to round-trip to identical bytes. That caught a
  real defect in the witness protocol: `UnmarshalAddCheckpoint` decoded proof nodes with
  a non-strict base64 decoder, so `"00000000001="` and `"00000000000="` produced the
  same request. Every other parser in the project already used `.Strict()` for the same
  construct; this one was the outlier. Fixed, with the failing input kept as a corpus seed.

## [0.1.0-alpha] — unreleased

First tagged version. The success criterion of the project
(`docs/CONCEPTO-v1.2-es.md` §18) runs end to end and is automated in
`scripts/demo-criterio-exito.sh`.

### Core ledger

- Signed block headers: RFC 8785 (JCS) canonical form, SHA-256 digest, Ed25519
  signature, hash-chained. Chain verification enforces the expected signer.
- RFC 6962 Merkle tree with inclusion proofs (RFC 9162 §2.1.3) and consistency
  proofs (§2.1.4), verified against the official RFC test vectors.
- Native RFC 8785 canonicalization, passing the official vectors, with fuzzing.

### Storage

- SQLite append-only store (pure-Go driver, no cgo): WAL, `synchronous=FULL`,
  triggers rejecting UPDATE and DELETE on the ledger tables.
- Integrity verification on open. A cosigned checkpoint lets the fast path skip
  Ed25519 verification below it; `VerifyFull` recomputes everything.
- `OpenResult` reports whether the history is **attested**, because "the file
  opened cleanly" and "the history is complete" are different claims.
- Durable anti-rollback lock: a signed checkpoint is persisted before it leaves
  the process, so a crash between signing and cosigning cannot make the log
  contradict itself after a restart.

### C2SP interoperability

- Signed checkpoints (`c2sp.org/tlog-checkpoint`) over `x/mod/sumdb/note`.
- Witness cosignatures (`c2sp.org/tlog-cosignature@v1`, algorithm byte `0x04`).
- Full HTTP witness protocol (`c2sp.org/tlog-witness`): `add-checkpoint` with the
  complete status-code table, and the monitoring endpoint. The exact spec commit
  and its SHA-256 are pinned in ADR-011.
- Witness state persisted in its own SQLite database, with the consistency check,
  the signature and the write inside a single immediate transaction — the
  race the specification describes in detail.
- Offline-verifiable receipts (`c2sp.org/tlog-proof`).
- ML-DSA-44 (FIPS 204) as an additional log signature, via the `0xff` extension
  mechanism of `signed-note` with a Núcleo identifier. Verifiers that only know
  the Ed25519 key keep working unchanged.

### Keys, privacy and deletion

- Argon2id (t=3, m=64 MiB, p=4) → KEK → per-vault random DEK, wrapped with
  XChaCha20-Poly1305 and AAD bound to the vault identifier.
- Payload blobs encrypted with AAD = `tenant ‖ payload_hash`, fixed-length so the
  concatenation is unambiguous.
- **Erasable payloads**: deleting a blob satisfies data-deletion rights while the
  chain stays verifiable and previously issued receipts stay valid.
- SLIP-0039 backup of the KEK (2-of-3 by default), verified by round-trip before
  the cards are shown, across every share so a single mis-printed card cannot
  slip through.
- HMAC-SHA-256 commitments with a per-tenant subkey derived from the DEK via
  HKDF, for values too guessable to travel as a bare hash.

### Witness synchronization

- `logsync` returns success only when it holds a verified cosignature covering
  the current local size and root. There is no shortcut, which is what stops a
  replayed but genuine old checkpoint from silencing a truncated ledger.
- Rollback detection with both sizes reported, so the operator learns how many
  blocks are missing rather than a status code.

### Reconciliation

- Compares the live system against what was sealed, reporting verified,
  altered, missing and never-sealed records, with the sealed hash and the
  declared sealing time of each finding.
- `IncludeFullVerify` runs the exhaustive ledger verification as part of the
  sweep — the scheduled execution promised by the ADR-009 amendment.

### Receipts

- Human-readable header derived from the proof, with declared and provable time
  labelled apart. Parsing re-derives it and requires a byte-for-byte match, so a
  receipt whose visible text contradicts its bytes is rejected.
- Provable time counts only cosignatures that verify under the caller's policy.

### CLI (`cmd/nucleo`)

- `init`, `seal`, `status`, `verify`, `receipt`, `reconcile`, `sync`,
  `witness serve`, `witness key`, `backup`, `restore`.
- Passphrase read from the terminal without echo, or from a file. Never from an
  argument: arguments are visible in the process list.
- Documented exit codes: `0` success, `1` usage, `2` verification failed,
  `3` witness sync failed.
- `--json` on every command, with no prose mixed into the stream.

### Ecuador profile (`profiles/ecuador`)

- `ecuador.sri.factura.v1`: módulo-11 access-key validation, field extraction,
  and classification of which fields must travel as commitments.
- `ecuador.sas.acta.v1`: shareholder-meeting minutes, one commitment per
  attendee.
- The XML is sealed byte-for-byte and never re-serialized, so its XAdES
  signature survives.

### TypeScript verifier (`sdk/ts`)

- `@nucleoledger/verify`: parses signed notes, checkpoints, tlog-proofs and
  receipts; verifies Ed25519 and SHA-256 through WebCrypto, the RFC 9162
  inclusion path, cosignatures against a policy, and the receipt header.
- **Zero runtime dependencies.**
- Reads the same `testdata/vectors/` files as the Go suite.
- `0.1.0-alpha.0` was published to npm **by hand and without provenance**
  (`--provenance=false`): provenance needs an OIDC token that only CI holds, and
  npm's trusted-publisher configuration cannot be created before the package
  exists. Releases from `.github/workflows/publish-npm.yml` carry it.

### Static verifier (`web/verify`)

- One HTML page, no network, no framework. Paste or drop a receipt and a policy
  and see the verdict, both clocks, and the reasons for a rejection.

### Documentation

- `docs/PROTOCOL.md` (normative), twelve ADRs including the amendments where a
  measurement contradicted an earlier assumption, `docs/TUTORIAL-es.md`,
  `docs/RELEASING.md`.

### Known limitations

- No external security audit has been performed.
- A block's signature is not inside its Merkle leaf, so a cosigned root does not
  pin it; `verify --full` is the check that does.
- A receipt's recipient is not covered by any signature.
- A network adversary can prevent detection, though noisily; it cannot forge
  attestation.
- Witness cosignatures are Ed25519, not ML-DSA-44, which `tlog-witness` states as
  a SHOULD.

[Unreleased]: https://github.com/nucleoledger/nucleo/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/nucleoledger/nucleo/releases/tag/v0.1.0-alpha
