# Núcleo Protocol Specification

**Version: 0.4-draft (decisions frozen 2026-08-31; leaf rule changed 2026-09-10; policy and signature-block rules made normative 2026-09-12; time resolution fixed at one second 2026-09-13; wire formats stabilize at v1.0)**

> **0.3-draft changes what a verifier ACCEPTS, not what an issuer emits**
> ([ADR-018](adr/ADR-018-politica-formato-de-cable.md)). Every receipt produced under
> 0.2-draft by the reference implementation still verifies. What is now rejected:
> verification policies without witnesses, without `quorum` or with `quorum: 0`, with
> upper-case hex, with duplicated or case-variant keys (§3.2); and signed-note
> signature blocks that 0.2-draft verifiers read leniently (§3.3).

> **0.2-draft is a BREAKING change to the Merkle leaf and to the receipt format**
> ([ADR-014](adr/ADR-014-hoja-y-firma.md), [ADR-015](adr/ADR-015-destinatario.md)).
> Every root, every checkpoint and every receipt produced under 0.1-draft is
> incompatible with 0.2-draft. There is **no migration path, because there is
> nobody to migrate**: `v0.1.0-alpha` was published one day earlier, has no known
> deployments and no third-party receipts. Doing this after someone depended on it
> would have cost a permanent second code path in every verifier — see §2.1 on why
> the leaf rule is now versioned so this is never again a "now or never".

This document is normative. Implementations MUST follow it. Changes require an ADR in `docs/adr/` and a version bump here. Terms MUST/SHOULD/MAY follow RFC 2119.

## 1. Block format (implemented)

A **block** is `{header, hash, signature}`. The **header** is the signed part:

| Field | Type | Rule |
|---|---|---|
| `index` | uint64 | Sequential from 0 (genesis). MUST be ≤ 2^53 − 1 |
| `prev_hash` | hex(32B) | SHA-256 hex of previous block; genesis uses 64 zeros |
| `timestamp` | string | RFC 3339, **one-second resolution, no fractional part**, MUST be UTC (`Z` suffix), non-decreasing |
| `tenant` | string | Organization identifier (e.g. RUC). Non-empty |
| `type` | string | Record type, e.g. `sri.factura.v1`. Non-empty |
| `payload_hash` | hex(32B) | SHA-256 of the exact payload bytes (see §5) |
| `payload_cid` | string | Reference to the encrypted blob stored outside the log |
| `signer_pubkey` | hex(32B) | Ed25519 public key of the tenant signer |

- `hash = SHA-256( JCS(header) )` where JCS is RFC 8785. Implementations MUST pass the official RFC 8785 test vectors.
- `signature = Ed25519(sk, hash)` — the 32-byte digest is signed, not the JSON, so a verifier holding only hashes can check signatures.
- The signature MUST be deterministic. Ed25519 (RFC 8032) is, and §2.1 depends on it: the leaf commits to the signature bytes, so a signature that varied between runs would change the tree. Any future signature algorithm for blocks MUST use its deterministic variant.
- Chain rules: `index` consecutive, `prev_hash` matches, timestamps non-decreasing, and full-chain verification MUST enforce an expected signer key.
- **Time resolution** ([ADR-019](adr/ADR-019-resolucion-temporal.md)). An implementation MUST NOT sign a header whose `timestamp` carries a fractional second: the signed domain is the same one the attestation uses, since `tlog-cosignature@v1` timestamps are whole Unix seconds (§4). A verifier MUST accept a fractional `timestamp` — receipts issued before this rule carry one, inside the signature and inside the leaf — and MUST NOT reformat it (§3.1). A `timestamp` with a UTC offset instead of `Z` MUST be rejected in both cases: one instant, one text.
- Ordering is `index` with `prev_hash`, never the clock. Two blocks sealed in the same second are ordered by the chain, and `timestamp` is declared time (§4).

## 2. Merkle tree (implemented)

RFC 6962 with SHA-256: leaf hash = `SHA-256(0x00 ‖ leaf_data)`, node = `SHA-256(0x01 ‖ l ‖ r)`. What `leaf_data` *is* is a versioned rule: see §2.1. Inclusion proofs verified per RFC 9162 §2.1.3.2. Consistency proofs (RFC 9162 §2.1.4) are implemented. Domain extension: for oldSize == newSize the proof MUST be empty and verification additionally requires byte-equality of the two 32-byte roots; the RFC defines proofs only for 0 < m < n, so any cross-language implementation MUST adopt this same convention to stay interoperable. Proof nodes have no bespoke wire format: they serialize as one base64 (RFC 4648 §4) hash per line, exactly as consumed by c2sp.org/tlog-proof; the in-memory [][]byte representation is not a wire format. Both roots MUST be exactly 32 bytes; verification fails closed otherwise.

### 2.1 Leaf rule (versioned, normative)

What a leaf commits to is a **named version**, not an implementation detail. This
section exists because changing it silently is impossible-in-practice once anyone
holds a receipt, and the project reached that point once without the vocabulary to
manage it.

| version | `leaf_data` | length | status |
|---|---|---|---|
| `leaf/v1` | `hash` | 32 B | **historical.** Produced by 0.1-draft. No deployment should use it. |
| `leaf/v2` | `hash ‖ signature` | 96 B | **current.** |

`leaf/v2` bytes, exactly — both fields RAW, not hex, in this order, with no
separator and no length prefix:

```
leaf_data = hash(32 raw bytes) ‖ signature(64 raw bytes)        // 96 bytes
leaf_hash = SHA-256( 0x00 ‖ leaf_data )                          // RFC 6962
```

No separator is needed and none is allowed: both fields are FIXED length, so the
concatenation is unambiguous. (A variable-length field here would reintroduce the
AAD ambiguity that ADR-009's external audit found; fixed lengths are what make it
safe.)

**What v2 buys, precisely.** Under `leaf/v1` a cosigned root said nothing about the
`signature` column: an adversary with write access could destroy or garble every
signature and the fast open path, which only rehashes stored headers, still
reported the history as attested. `verify --full` caught it, and nobody runs
`verify --full`. Under `leaf/v2` the check that already happens on open covers the
signatures, and a receipt holder can verify the block signature — under v1 they had
no route to it at all, since the receipt did not carry the signature.

> **Amendment 2026-09-12 (ADR-016), after the adversarial audit.** The sentence
> above — *"the check that already happens on open covers the signatures"* — was
> **falsified by measurement two days after it was written.** The open-path check
> only covers the signatures *below a checkpoint it trusts*, and the audit showed
> that the checkpoint it trusted could be **fabricated by the same adversary**: a
> note with the recomputed root and a 76-byte signature blob of invented bytes,
> which `IsCosigned` accepted on shape alone. The open path never verified the log
> signature on stored checkpoints. So `leaf/v2` raised the bar only against an
> adversary who could write `blocks` but not `checkpoints` — a division no real
> adversary respects. The sentence is left in place, struck through in spirit,
> because this project records when a measurement contradicts a claim rather than
> rewriting the claim.
>
> What is true after ADR-016: a stored checkpoint counts as attestation **only if
> verified** — its log signature against the key the ledger itself declares, AND
> its witness cosignatures under a policy supplied by the caller *from outside the
> file*. Without that policy the open path reports "checkpoint present, not
> verified" and takes no shortcut. With it, `leaf/v2` delivers what the paragraph
> above promised, because the boundary it trusts is now one the adversary cannot
> draw. The regression test is the audit's exploit, verbatim
> (`internal/store/exploit_test.go`).

**What v2 does NOT buy.** Nothing changes for an adversary holding the tenant key,
and nothing changes about truth of content. `signer_pubkey` lives inside the
header, so it was already pinned by the root under v1.

**Rules for any future change** (this is the part that must outlive the change
itself):

1. A change to what a leaf commits to MUST be a **new version** with a new name.
   An existing leaf version MUST NOT be edited.
2. The leaf version in force MUST be **machine-readable** wherever a verifier
   needs it: a log records it at creation and MUST refuse to open a log created
   under a different one; the receipt's magic carries it (§3.1).
3. A segment MUST NOT contain two leaf versions. A migration closes the current
   segment with a final attested checkpoint under the old rule and opens the next
   segment under the new one (ADR-006), with the chain between segments verified by
   RFC 9162 §2.1.4 consistency proofs between closing checkpoints. This is the
   route that did NOT exist for the v1→v2 change, and its absence is what made that
   change a one-time opportunity rather than a routine migration.

## 3. C2SP artifacts (normative, pending implementation)

Núcleo is a C2SP-compatible log. Pinned specs (record exact versions in ADR-001 when implemented):

- **Checkpoint**: `c2sp.org/tlog-checkpoint` — signed note with origin line, tree size, root hash. A log MUST NOT sign a checkpoint inconsistent with any previously signed one. Origin line: `nucleoledger.com/<tenant-log-id>` (final scheme fixed at first release). Núcleo emits exactly three body lines; the parser currently rejects extension lines (fail closed). Verbatim-preserving parsing is required before witnessing third-party logs.
- **Log signature**: Ed25519 signed-note signature (type 0x01) REQUIRED. Key ID algorithm bytes are distinct per role and enter the key ID hash: log signature: signed-note type 0x01; witness cosignatures: c2sp.org/tlog-cosignature@v1 with key ID algorithm byte 0x04 (0x06 reserved for future ML-DSA-44 cosignatures). An additional **ML-DSA-44** cosignature-style signature SHOULD be added (verifiers ignore unknown signatures, so this is backward-compatible).
- **Witness cosignatures**: `c2sp.org/tlog-cosignature@v1` (72-byte timestamped_signature). Witness protocol: `c2sp.org/tlog-witness` — the witness MUST persist the new checkpoint atomically with the consistency check before responding (rollback-race prevention).
- **Receipt / proof bundle**: `c2sp.org/tlog-proof` — self-contained offline-verifiable proof (checkpoint + cosignatures + index + inclusion proof + extra data). The Núcleo *receipt* IS a tlog-proof plus a human-readable wrapper. QR codes carry a URL to the static verifier + the entry hash, NOT the full proof.
- **Archived segments**: `c2sp.org/tlog-tiles` static tiles.

### 3.1 Receipt format (normative)

A Núcleo receipt is a human-readable text block, a separator line, and a machine
section. The **magic on the first line fixes both the receipt format and the leaf
rule it is verified under**, so a verifier never has to guess:

| magic | leaf rule | status |
|---|---|---|
| `nucleo.org/receipt@v1` | `leaf/v1` | historical; verifiers MAY refuse it outright |
| `nucleo.org/receipt@v2` | `leaf/v2` | **current** |

The human-readable section is **derived** from the machine section, never authored:
a verifier MUST re-render it and require byte equality. Fields that come from the header
are carried **verbatim**: a verifier MUST NOT parse and reformat them, `timestamp`
included ([ADR-019](adr/ADR-019-resolucion-temporal.md)). Reformatting a signed field
invents a second representation of it, and two representations end in two verifiers
that disagree — which is exactly what happened: Go printed the declared time without its
fractional second and TypeScript printed the header's literal, so a genuine receipt was
accepted by one and rejected by the other. It carries the recipient, the
issuer, the record type, the payload hash, the block index, both clocks labelled
separately (§4), and a legal notice. The notice and the recipient label are inside
that byte-equality check on purpose: a receipt with either one removed does not
verify.

Machine section of `receipt@v2`, one item per line, in this order:

```
<JCS(header)>                     canonical header bytes, exactly as signed
<base64(signature)>               the block's 64-byte Ed25519 signature
— <tenant> <base64(receipt_sig)>  the ISSUER's signature over the whole receipt
<c2sp.org/tlog-proof@v1 …>        index, inclusion path, and the checkpoint note
```

The block signature is on the wire because `leaf/v2` needs it: without it the holder
cannot recompute `leaf_data` and therefore cannot verify inclusion at all. It MUST be
base64 (RFC 4648 §4) of exactly 64 raw bytes, canonically encoded.

A verifier of `receipt@v2` MUST:

1. recompute `hash = SHA-256(JCS(header))` from the header bytes it received, and
   require the received bytes to BE the canonical form;
2. verify the block signature against `header.signer_pubkey` — this is a route a
   `receipt@v1` holder did not have;
3. recompute `leaf_data` per §2.1 and verify inclusion against the checkpoint root;
4. verify the checkpoint's log signature and the witness cosignatures under a policy.

Step 2 is not redundant with step 3. Step 3 proves the log committed to these bytes;
step 2 proves the tenant key signed them. A root pins what the log published; a
signature says who authored it.

#### The issuer signature (normative)

```
receipt_sig = Ed25519( tenant_sk, SHA-256( receipt_bytes_without_the_signature_line ) )
```

It covers the **whole receipt**, recipient included — not the recipient alone. Signing
the recipient line by itself would let anyone recombine a signed line with a different
proof, which is how a signature becomes decoration.

The verifying key is `header.signer_pubkey`: the same key that signed the block. That
is the whole point, and it is why this required `leaf/v2` first. `signer_pubkey` lives
inside the header, the header is inside the leaf, and the leaf is under a root that
witnesses cosign — so the key a verifier should use is pinned by the same attestation
that pins everything else. **A verifier needs nothing beyond the receipt and its
policy: no key directory, no new PKI.** What it does need is the policy itself, and the
policy has to arrive authenticated by some other means — the counterparty must know it is
yours. This sentence used to say "no out-of-band exchange", which was wrong in the part
that matters: the exchange is not eliminated, it is reduced to one document that is the
same for every receipt you will ever issue, instead of one per key or per record
(corrected 2026-09-13, fourth audit).

A `receipt@v2` MUST carry this line, and a verifier MUST reject a receipt that lacks
it or whose signature does not verify. What it establishes: the issuer — and only the
issuer — produced THIS document for THIS recipient with THIS text, including the legal
notice. What it does **not** establish: delivery, or that the issuer did not also
issue a different receipt for the same record to somebody else. The recipient line is
therefore labelled `(firmado por el emisor)` and not, say, "delivered to".

The signed bytes depend on the issuer's verification policy, because the rendered text
contains the provable time and that only exists relative to a set of witnesses. A
recipient whose policy differs already rejected such a receipt on the text
byte-equality rule; the signature inherits that constraint rather than adding one.

### 3.2 Verification policy (normative)

The policy is everything a verifier brings from OUTSIDE the artifact it verifies
(ADR-017). It is a wire format: the CLI (`--policy-file`), the TypeScript SDK and the
static verifier MUST accept and reject exactly the same documents.

A policy document is RFC 8259 JSON, UTF-8 without BOM, at most 65536 bytes, whose only
value is an object with these members:

| member | type | rule |
|---|---|---|
| `origin` | string | REQUIRED, non-empty |
| `logKey` | string | REQUIRED, exactly 64 characters from `[0-9a-f]` |
| `signerKey` | string | OPTIONAL in the format; REQUIRED to verify a receipt |
| `witnesses` | object | REQUIRED, at least one member; every name non-empty; every value exactly 64 characters from `[0-9a-f]`; no public key under two names |
| `quorum` | integer | REQUIRED; a JSON number literal matching `-?(0\|[1-9][0-9]*)` (no fraction, no exponent); `1 ≤ quorum ≤ count(witnesses)` |

A document MUST be rejected if, at any depth:

- an object has two members whose names are equal after unescaping;
- a member name is not one of the above — including a name that differs from one of
  them only in letter case;
- any value is `null`;
- anything other than JSON whitespace follows the top-level object.

There is no witness-less receipt policy. A verifier MUST NOT treat a missing `quorum`
as zero. If a witness-less mode is ever introduced it will be an explicit, separately
named member, never a default.

When a ledger is opened with a policy, `origin` and `logKey` MUST equal the values the
ledger declares, and `signerKey`, when present, MUST equal the key that signs every
block (ADR-017).

### 3.3 Signed-note signature block and cosignature counting (normative)

A Núcleo verifier MUST read the signature lines of a checkpoint note itself, with
these rules, and MUST NOT rely on a signed-note library's leniency:

1. The note is valid UTF-8 containing no control character other than `\n` (U+0000–U+001F).
   Text and signatures are split at the LAST `\n\n`; the signature block is
   non-empty and ends with `\n`.
2. EVERY line of the signature block has the form `— <name> <base64>` (U+2014, space,
   name, space, base64). A line that does not is a malformed note.
3. `<name>` is non-empty, contains no `+`, and contains none of: U+0009–U+000D, U+0020,
   U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000.
4. `<base64>` is RFC 4648 §4 standard base64, canonically encoded, decoding to at
   least 5 bytes; the first 4 are the key ID.
5. At most 100 signature lines.

Counting:

- A line whose (name, key ID) belongs to a key of the policy — the log key or a
  witness key — MUST verify. If any such line fails, the note is invalid, even if
  another line for the same key verifies.
- A witness counts ONCE toward the quorum, however many lines it has.
- A witness's time is the EARLIEST timestamp among its cosignature lines that verify;
  the provable time (§4) is the minimum across counted witnesses. The order of the
  lines, which the issuer chooses, MUST NOT affect the result.
- Lines of keys the policy does not know are ignored (c2sp.org/signed-note).

## 4. Time (normative)

- The block `timestamp` is **declared time** (local clock; can lie), at one-second resolution (§1).
- **Provable time** of an entry = the earliest external attestation covering it: minimum of witness cosignature timestamps, and RFC 3161 TSA tokens if configured.
- Receipts MUST label both values separately. Documentation MUST NOT present declared time as proof.

## 5. Payloads (normative)

- Externally signed documents (SRI XML with XAdES-BES, PDFs) are hashed **byte-for-byte, never re-canonicalized**.
- JSON payloads authored by Núcleo profiles are canonicalized with JCS before hashing. Monetary amounts and identifiers MUST travel as strings.
- Low-entropy / guessable values (IDs, amounts, statuses) MUST NOT be committed as bare hashes. Use a **VRF commitment** (`c2sp.org/vrf-r255`) when third-party verifiability without key disclosure is needed; HMAC-SHA-256 with a tenant secret otherwise. (Pending implementation; format fixed in ADR-003.)
- The ledger stores only commitments. Sensitive payloads live in **erasable encrypted blobs**: XChaCha20-Poly1305, random 24-byte nonce, `AAD = tenant ‖ payload_hash`. Erasure of blob + key removes the content while the chain stays intact. Whether that
satisfies a particular deletion right is a legal question about a particular regime and a
particular deployment — what remains is the `payload_hash` and the commitments, which are
data about the erased document. The protocol states the technical fact and takes no
position on the legal one (corrected 2026-09-13, fourth audit).

## 6. Keys (normative, pending implementation)

- Signing identity: Ed25519 per tenant.
- At-rest hierarchy: passphrase → Argon2id → **KEK**; random 32-byte **DEK** per vault, wrapped by KEK.
- Backup: **SLIP-0039** mnemonic shares protecting the KEK, default threshold 2-of-3 (3-of-5 for multi-partner orgs). Guided backup UX is a v1 requirement.
- Identity rotation: a special block type signed by the outgoing key authorizing the new key. If the old key is lost: new identity anchored via witnesses + an out-of-band partner attestation; the discontinuity MUST be visible in the chain.

## 7. Segments (normative, pending implementation)

Periods (monthly or yearly by volume) close with a witnessed checkpoint. Historical segments are archived as static tiles. Cross-segment verification uses RFC 9162 consistency proofs between closing checkpoints (Rekor-v2-style sharding).

## 8. Storage (normative)

SQLite, pure-Go driver, WAL, `synchronous=FULL`, single writer. The blocks table MUST carry BEFORE UPDATE/DELETE triggers that abort. Triggers are a guardrail, not the security boundary — witnesses are.

## 9. Deployment modes

1. **CLI (primary)**: `nucleo seal|verify|...` invocable per execution (shared-hosting compatible).
2. **Daemon (optional)**: localhost HTTP / Unix socket, OpenAPI-described; thin clients per language (TS → PHP → Python → Java).
3. **Go module**: direct import for Go integrators.

## 10. Out of scope of the protocol

Legal validity claims, truth of original content, and protection against an adversary who controls keys, ledger, and all witnesses with no receipts issued. Documentation language: "designed to align with" LOPDP / ISO 27001 / ISO 27037 — never "certified" without formal backing.
