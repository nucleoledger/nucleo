# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the on-disk format and the wire formats may
change between minor versions. What will **not** change silently: the CLI exit
codes, and any golden test vector in `testdata/vectors/`.

## [Unreleased]

### Security: second external audit, and the PHP SDK's first real bug (Sprint 9)

The same external reviewer read the tree again at `ffd5cf1`. Both audit reports are now
**in the repository** — [2026-09-13](docs/auditoria-externa-20260913.md), recovered
verbatim from the session that produced it, and
[2026-09-19](docs/auditoria-externa-20260919.md) — so the ADRs that cite them point at
something a reader can check. One of those citations turned out to be false and is
amended in place, which is the whole argument for versioning the source.

- **HIGH — the PHP sealer accepted a policy and never passed it to the binary.** The
  constructor stored `$policyFile`; `seal()` and `status()` built their arguments without
  `--policy-file`. An ERP could configure the trust root of
  [ADR-017](docs/adr/ADR-017-politica-raiz-de-confianza.md) and seal without it for
  months: attestation, freshness and signer identity came back unverified and nothing said
  so. A parameter that *appears* to configure something and does not is worse than not
  offering it. Fixed in the common path, plus the two tests the auditor asked for — one
  reads the command line through a **fake binary**, the other proves with the real one
  that `signer.verified` flips to `true` and that a foreign policy exits 2. Removing the
  fix again fails 9 assertions. A sweep of every property and parameter in the SDK found
  no other stored-and-unused value.
- **MEDIUM — the `--json` output is a wire format, and now gets that treatment**
  ([ADR-025](docs/adr/ADR-025-json-como-formato-de-cable.md)). `SealResult::fromJSON` read
  the CLI with casts and defaults: measured against this release's invalid vectors, the
  old reader **accepted 25 of 29**. The two worst were not theoretical — `attestation:
  "none"` with `attested: true` read as attested, and a missing `freshness` object read as
  `stale: false`, which is what a cron looks at to stay quiet. Now: a strict reader
  (`Nucleo\Contract`), a typed `SealContractError`, and
  `testdata/vectors/cli-json/` — 8 valid vectors emitted by the real CLI (including the
  fully attested state, with a witness cosigning) and 29 invalid ones written by hand. The
  Go side regenerates and **compares** them, so a change in the CLI's output fails there
  instead of in an integrator's cron. `docs/CLI-JSON.md` is normative.
- **LOW — `sas.acta.v1` was announced in "What works today" and is not wired into the
  CLI.** Corrected in the README, and the reason is written down: an acta's payload comes
  from the public commercial registry, so it is the enumerable document
  [ADR-023](docs/adr/ADR-023-payload-hash-y-enumeracion.md) §C addresses — wiring it needs
  a random member the profile does not yet have. A test now pins the exposed profile list,
  because nothing did, which is how the docs got ahead of the code unnoticed.
- **Reproducibility.** The auditor could not run PHP, so they reproduced two verifiers out
  of three and said so. `CONTRIBUTING.md` now carries the recipe — `ext-sodium` per
  platform, the readiness check, and `NUCLEO_DIFERENCIAL_EXIGE_PHP=1`, which turns a
  missing PHP from a printed warning into a failed run.

### Added: the PHP SDK, and sealing that survives a retry (Sprint 8)

The external audit's product findings, and the ERP that seals from PHP.

- **A PHP SDK, split by role** ([ADR-021](docs/adr/ADR-021-sdk-php.md)): `Nucleo\Verifier`
  is **native**, written from `PROTOCOL.md` rather than ported, because whoever verifies is
  the counterparty and asking them to run the issuer's binary to check the issuer's receipt
  is asking them to trust what they are checking. `Nucleo\Sealer` **wraps the Go binary**,
  because the ledger must have exactly one writer: the writer holds invariants that are not
  in the format, and what it writes is append-only in a customer's file. No composer, no
  dependencies beyond `ext-sodium` and `ext-json`. It joined the differential as the third
  verifier on day one and agreed with Go on **3.314 receipt mutations and 9.929 policy
  documents, zero verdict divergences** on the first full run — both clocks, the index, the
  recipient, the signer key, which witnesses counted, which signatures were ignored.
- **Sealing the same payload twice used to be four different behaviours**
  ([ADR-020](docs/adr/ADR-020-idempotencia-y-atomicidad-del-sellado.md), H8). Encrypted: exit
  1 with a raw `UNIQUE constraint failed: blobs.payload_hash (1555)`. With `--no-encrypt`: a
  new block, silently. After a failure between the blob and the block: an orphan that made
  that document **impossible to seal ever again** in that ledger — worse than reported. From
  another tenant: the same dump. Now: re-sealing is a legitimate new block **that says which
  block it duplicates**, the blob and the block and the commitments and the idempotency key
  go in **one transaction**, a second tenant's identical content is refused with the reason
  (its ciphertext is bound to its tenant by the AAD), and `--idempotency-key` makes a retry
  after a timeout write nothing and answer what the original seal answered.
- **No internal database error reaches the user**, and the rule is checkable: `store`
  classifies driver errors by SQLite result code — never by message text — and a test walks
  the failure paths, with and without `--json`, failing if any message mentions `sqlite`,
  `constraint`, `SQL logic` or a result code in parentheses.
- **A comparison that cannot be made is not a verdict**
  ([ADR-022](docs/adr/ADR-022-comparacion-imposible-no-es-veredicto.md), H7). Identity
  comparison was skipped when `vault_meta` lacked the rows to compare against, and skipping
  it returned success — the pattern [ADR-016](docs/adr/ADR-016-atestacion-en-la-apertura.md)
  closed for attestation, in another place. `vault_meta` is mutable by design, so deleting
  two rows disabled both checks and a substituted ledger opened clean under the victim's
  policy. Verified by removing the fix and watching the exploit work again.
- **`payload_hash` confirms a guess of the whole document, and the field-level commitments
  do not cover that** ([ADR-023](docs/adr/ADR-023-payload-hash-y-enumeracion.md), H10).
  Reproduced: a four-value template document recovered from the header on the first try.
  The hash stays a bare SHA-256, because it is the only thing that lets a counterparty tie
  **their** document to the record with no keys and no PKI; PROTOCOL 0.5-draft §5 now states
  the limit normatively and puts the entropy where it belongs — inside the payload, added by
  whoever authors it, never by Núcleo, which must hash the exact bytes it was handed.
- **The last golden vector Go authored is gone**
  ([ADR-024](docs/adr/ADR-024-material-mldsa-de-los-vectores.md)). The Python oracle now
  builds all eighteen receipt vectors and borrows only the 3.732 bytes of ML-DSA-44 key and
  signature that no verifier checks — recomputing even that line's key ID from the spec, and
  refusing stale material whose signature is over a different note body. The oracle's vector
  came out byte-for-byte identical to the one Go used to write.
- The replay warning got its own threshold: **15 minutes**, not the 72-hour freshness one. A
  cosignature replayed ten minutes ago used to trigger nothing, and ten minutes is all a
  replay needs while the log does not grow.

### Security: fourth adversarial audit — the first external one (Sprint 7f)

A model with no access to this repository's history read the public tree at `1c53e1c` and
reported six findings and six published claims it judged false or too broad. The claims
turned out to matter more than the code.

- **CRITICAL — a genuine receipt was rejected by the SDK and the page.** Reproduced end to
  end with the production binary: `ledger.NewHeader` signed `RFC3339Nano`, the Go renderer
  printed the declared time **without** its fractional second, and TypeScript re-printed
  the header's literal. Go accepted the receipt; the SDK and the page rejected it. It
  happened whenever the clock did not land on a whole second — nearly always.
  [ADR-019](docs/adr/ADR-019-resolucion-temporal.md) fixes the signed resolution at one
  second and makes every implementation carry the header's literal instead of reformatting
  it (PROTOCOL 0.4-draft). Receipts re-issued from a fractional block now verify in all
  three; receipt **files** already delivered with the truncated line are rejected by all
  three instead of by two.
- **HIGH — the attested root was not always checked.** The open path only compared the
  attested note's root with the tree when its size differed from the last note's, inferring
  "same note" from "same tree_size". With the table rebuilt (the threat model allows a
  writable file) and a log that signed a fork, the open granted `verified` without ever
  looking at the root behind the shortcut. Now it always checks.
- **HIGH — a crash any third party could trigger.** `Parse` on a receipt whose
  `signer_pubkey` was shorter than 16 characters panicked on a fixed-length slice in an
  error message. A server accepting receipts fell over on demand. All five such slices are
  now bounded, with regressions that do not recover the panic.
- **MEDIUM — a replayed exchange passes for current contact.** With the ledger parked,
  replaying a genuine older GET and POST makes `sync` succeed without the witness being
  contacted. The cosignature is real; what it cannot do is get younger, so `sync` now warns
  and reports `replay_suspect` where it happens instead of leaving it to the next `status`.
- **MEDIUM — TypeScript checked key order, not canonical JCS.** Duplicate members,
  whitespace and alternative escapes passed there and were rejected by Go. And Go did not
  compare the proof's index with the header's, which TypeScript did.
- **LOW — a witness named `__proto__` vanished** from the TypeScript policy map, silently
  turning a two-witness policy into one.
- **LOW — freshness mixed up two questions.** With a log that has no new blocks, `status`
  said the cron had been broken for days while it ran hourly, because the stored note is
  the *first* of its size. Freshness now measures the last verified contact and the JSON
  publishes `first_attested_at` for "since when it is on record"; a receipt's provable time
  is still the minimum.

#### The claim that mattered most

*"Every golden value is computed outside the code under test"* was **false** exactly where
the project stakes its credibility. The receipt vectors were generated by
`internal/receipt` and rewritten by its own test suite on every run. They now come from
[`testdata/vectors/receipt/generar.py`](testdata/vectors/receipt/generar.py), an oracle
built from the specification that imports no Go; the Go suite only reads them, and a
`TestMain` fingerprint fails the run if anything rewrote them. First comparison: sixteen of
seventeen vectors byte-identical, and the seventeenth exposed a real defect in the Go
exporter. Five more claims — bare hashes, the network adversary, freshness, the out-of-band
exchange, and deletion rights — are corrected in place, where they were published.

#### Oracle, not counters

The receipt fuzzer had been running with a policy that made `Parse` reject everything at
line one, so its acceptance branch and round-trip property had never executed. And the
differential compared one boolean. It now compares the whole verdict — both times, index,
recipient, signer key, counted witnesses, ignored signatures, checkpoint — whenever both
accept, and on its first run it found a real asymmetry: TypeScript separated the log's own
ML-DSA-44 signature from "keys you do not know" and Go still counted it as ignored.

### Security: third adversarial audit (Sprint 7e)

The third pass found nothing new in the receipt bytes — 2,269 CI mutations and 132
more of its own, zero divergences — and everything next to them: the policy file and
the note's signature block, which Go and TypeScript read differently. The sprint's
thesis is [ADR-018](docs/adr/ADR-018-politica-formato-de-cable.md): **the policy is a
wire format** and gets the same treatment as the others — a strict grammar in
PROTOCOL.md, shared vectors, and a differential.

- **HIGH — a duplicated cosignature line met the quorum in TypeScript and on the page.**
  An issuer with one colluding witness duplicated its line, re-signed the receipt and
  passed a 2-of-2 policy (`cosigners: ["w1","w1"]`); Go rejected it, because x/mod drops
  repeated signatures. A witness now counts once. The class is closed with a **second
  differential catalog of mutations re-signed by the issuer** — duplicate, reorder, graft
  and remove note lines, then `receipt.Sign` — which found **38 more divergences** on its
  first run: the TS note parser skipped malformed lines Go rejected. Both now apply
  PROTOCOL.md §3.3 line by line, and both reject non-canonical base64 in a signature
  line, which *both* had accepted.
- **HIGH — the fail-stale alarm could be silenced with `--policy-file`.** Delete the
  checkpoints and insert a fresh local record: attestation fell to `none`, freshness fell
  to the forged record, and `status`, `seal` and `verify` stayed quiet with exit 0. With a
  policy, the local record never feeds freshness now (`stale: true`, `source: "none"`,
  `policy: true`, warning on stderr). The docs/CLI-JSON.md sentence the audit falsified
  is amended in place.
- **MEDIUM — `seal` and `sync` never compared the chain signer with the vault key.** On a
  chain rewritten with another key, `seal` appended a legitimate block and said `ok`,
  and a first `sync` got the witness to cosign the foreign history. Both refuse now
  (exit 2) before writing or contacting the witness, and with a `signerKey` the open
  error names the first **intruding** block instead of the legitimate one.
- **MEDIUM — one policy file, two `signerKey`s.** `{"signerKey": A, "signerkey": B}` gave B
  to the CLI (case-insensitive matching, last wins) and A to the page. Policies are now
  read by a strict parser of our own in both languages: exact members, no duplicates or
  case variants, lower-case hex, integer-literal `quorum`, nothing after the object, no
  lone surrogates. 64 hand-written vectors in `testdata/vectors/policy/`, and a **third
  differential catalog** of 9,929 policy mutations, 0 divergences.
- **MEDIUM — a policy with no witnesses gave "✔ Recibo válido"** in Go, TS and the page.
  Receipt policies require at least one witness and `quorum ≥ 1`.
- **LOW** — two genuine cosignatures of one witness: Go took the first line, TS the
  earliest; the earliest verifying one now counts in both (PROTOCOL.md §3.3), with a
  vector. The same key under two witness names is a policy error. `--policy-file ""` is
  a usage error, a policy file with permissions other than 0600/0644 warns, and the open
  checks the policy's `origin`. `freshness.attested_ever` is true only with a verified
  attestation.
- **INFO** — `help --json` emits JSON; `init --json` requires an explicit
  `--assume-confirmed`; the page recognizes the log's own ML-DSA-44 signature instead of
  listing it under "keys you do not know"; two code comments that contradicted ADR-015
  and ADR-017 corrected.

#### ⚠ Breaking for verifiers: PROTOCOL 0.3-draft

What an issuer emits does not change; every receipt the CLI produces still verifies.
What a verifier **accepts** does: policies without `quorum`, with `quorum: 0`, without
witnesses, with upper-case hex, with duplicated or case-variant members, or with trailing
data are rejected; `Policy.quorum` and `witnesses` are required in the TypeScript type;
and a note signature block that 0.2-draft verifiers read leniently is invalid.

#### Performance

- The signer-continuity cost measured in 7d is recovered. `signer_pubkey` is read from
  the canonical header bytes instead of `json.Unmarshal`, backed by golden vectors
  computed in Python: **1.72–1.78 µs → 0.35–0.37 µs per block, 0 allocations**; opening
  10⁵ attested blocks **643–729 ms → 478–575 ms** (alternating runs, same machine).
- `scripts/bench-readme.sh` refuses a dirty tree and reports the median and range of N
  samples; the README table is regenerated with it from a clean checkout of the commit
  it cites.

### Security: second adversarial audit (Sprint 7d)

A second adversarial pass, run against the tree after Sprint 7c, looked for what the
first one had not: the block signer, the policy's edges, the freshness record, the
page, and the receipt vectors. Every finding below has its exploit as a regression
test; the differential and the two new exploit tests run in CI.

- **HIGH — nothing pinned the block signer.** Blocks 1–4 re-signed with the attacker's
  own key — self-consistent signatures, `signer_pubkey` pointing at that key — passed
  `verify --full`. [ADR-017](docs/adr/ADR-017-politica-raiz-de-confianza.md) makes
  the policy the single trust root: signer **continuity** (one key for the whole chain)
  is enforced on every open, policy or not; signer **identity** is checked against the
  policy's `signerKey`, which is required in receipt policies and optional when opening
  a ledger. Continuity has a measured price: the signer is read from every stored
  header, 1.9 µs per block, which is ~190 ms on a 10⁵-block open and makes the
  attested fast path ~35 % slower (alternating runs: 443–504 ms at the end of 7c,
  627–658 ms after). `status`/`verify` gain `firmante : ✔ verificado` / `◐ NO verificada`, and
  `--json` a `signer` object (`state`, `verified`, `pubkey`). The README sentence
  "`verify --full` catches it" is amended in place; it did not.
- **HIGH — an empty policy verified a forged ledger.** `OpenWithWitnesses(path,
  WitnessPolicy{})` and quorum 0 returned `verified` and took the fast path. A policy
  that cannot verify anything — no witnesses, quorum 0 or above the witness count, a
  bad key — is now rejected with `ErrPolicy` before the file is opened.
- **MEDIUM — freshness trusted a local record.** An `INSERT` into `log_state` with an
  invented witness and a fresh date made `status` print `frescura : ✔`. Freshness is now
  subordinated to the attestation: with a verified attestation it is the cosignature's
  own timestamp and the local record is not read; otherwise every sentence that leans
  on the record says so on the same line — "registro local, NO verificado" — and
  `--json` carries `freshness.verified` and `freshness.source` (`attestation` |
  `local_record` | `none`). `seal --json` and `reconcile --json` now expose
  `attestation`, `attested`, `attested_size`, `signer` and `freshness` with the same
  semantics as `status`.
- **MEDIUM — the page showed ✔ rows under a ✘ verdict.** No row is an unqualified ✔
  when `valid` is false; rows that are only *locally* true — a signature that checks
  against some key — are qualified as such.
- **MEDIUM — a policy file with another ledger's log key opened a fresh ledger.** The
  check lived only on the stored-checkpoint path. It now runs at the start of every
  open, with or without checkpoints.

#### Added

- **`--policy-file`** on `status`, `verify`, `seal`, `receipt`, `reconcile` and `sync`:
  one JSON file — `{origin, logKey, signerKey, witnesses, quorum}` — in exactly the
  format the TypeScript SDK and the static page already consume. `--signer-key` joins
  the loose flags. File and flags together is a usage error, not a merge; a repeated
  flag keeps its last value (standard `flag` semantics) and is documented as such.
- **`sync` prints the policy ready to save** after a verified attestation, and emits it
  as `policy` in `--json`. The test saves it verbatim and reopens with attestation *and*
  signer verified.
- **`docs/CLI-JSON.md`**: the contract of every `--json` output — conventions, shared
  objects (`signer`, `attestation`, `freshness`, `policy`) and fields per subcommand.
- **`scripts/bench-readme.sh`** regenerates the README benchmark table with date, commit
  and CPU. The table was refreshed with it; the old "~1 KB receipt" figure was for the
  proof section alone — a full receipt with legal notice and both signatures is ~5 KB.
- Receipt golden vectors at tree sizes 1, 2, 4, 8 and 9 (first and last index), plus a
  recipient that imitates a signature line; the differential iterates all of them.

#### Documentation

- `docs/TUTORIAL-es.md` re-executed end to end with the current binary. Step 5 is now
  built around the policy file `sync` prints; Step 7's policy carries `signerKey` (the
  old one is rejected by the page and the SDK); the "no keys to distribute" paragraph
  is replaced by why a counterparty needs your policy.
- `status` without a policy pointed to `--witness-name`/`--witness-key` for the
  attestation and to `--policy-file` for the signer on the same screen. Both now point
  to `--policy-file` first.

### Security: adversarial audit of 0.2-draft (Sprint 7c)

A fourth-model adversarial audit, run against the public repository the day after
0.2-draft landed, found one critical and one high finding — both in code written for
0.2-draft, both with executed exploits. Fixed in order, each as its own commit:

- **CRITICAL — the open path trusted unverified checkpoints.** See the amendment under
  "Breaking" below and [ADR-016](docs/adr/ADR-016-atestacion-en-la-apertura.md).
  `status`, `verify`, `seal` and `reconcile` gain `--witness-name`/`--witness-key`;
  without them the ledger opens but reports `attestation: "unverified"` and recomputes
  every signature (~8 s at 10⁵ blocks instead of 0.45 s — the price of not lying).
- **HIGH — receipt malleability and a Go/TS divergence.** Go verified the issuer
  signature over a clean *re-render*, TypeScript over the *received bytes*; a `\r`
  appended to base64 lines was accepted by Go and rejected by TS. `receipt.Parse` now
  requires the received machine section to be byte-identical to its re-serialization,
  and TS requires every base64 line to be canonical. A new CI job runs 212 mutations
  of the golden receipt through both verifiers and fails on any verdict divergence —
  it caught one more on its first run.
- **MEDIUM** — the static page labelled a recipient "(firmado por el emisor)" even when
  that signature had just failed. Now conditional, with a visible "NO VERIFICADO"
  mark on the same row.
- **MEDIUM/LOW** — `seal --tenant $'ACME\nS.A.'` produced a receipt no verifier could
  read while reporting success. Tenants must fit on one line.
- A test now pins the 76-vs-64-byte length check that stops a witness cosignature
  from being pasted in as the issuer signature.

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

  > **Amended 2026-09-12 after the adversarial audit.** The paragraph above framed the
  > residual gap as requiring "a dishonest issuer from the start, not an attacker who
  > comes later". **That framing was wrong**, and it was shown wrong by an executed
  > exploit: an attacker with write access, no keys and no witness rewrote a block,
  > recomputed its hash, fabricated a checkpoint over the new root with a 76-byte
  > signature blob of invented bytes, and `Open` reported `Attested=true`. The open
  > path never verified the log signature on stored checkpoints — it accepted them on
  > shape. Fixed by [ADR-016](docs/adr/ADR-016-atestacion-en-la-apertura.md): a
  > checkpoint counts as attestation only when *verified*, with the same machinery a
  > receipt uses, and the witness policy must come from outside the file. Without it,
  > `status` says "checkpoint present, NOT verified" and the open path takes no
  > shortcut. The exploit is now a regression test. The paragraph is kept because this
  > project records when a measurement contradicts a claim.

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
