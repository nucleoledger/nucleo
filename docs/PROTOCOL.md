# Núcleo Protocol Specification

**Version: 0.7-draft (decisions frozen 2026-08-31; leaf rule changed 2026-09-10; policy and signature-block rules made normative 2026-09-12; time resolution fixed at one second 2026-09-13; payload entropy made normative 2026-09-18; implementation-status amendments to §3, §6 and §9 on 2026-10-10, no normative change; erasure event registered in §5.1 on 2026-10-10; erasure authority added to §3.2 and §5.1 on 2026-10-11; wire formats stabilize at v1.0)**

> **0.7-draft changes when an erasure COUNTS** ([ADR-032](adr/ADR-032-autoridad-de-supresion.md)).
> Under 0.6-draft an erasure event counted if the tenant key signed it — and that key is opened
> by the passphrase that lives on the server. Under 0.7-draft it counts only if it carries an
> authorization by the **erasure key** of the verification policy, a key that is not on the
> server (§3.2 `erasureKey`, §5.1). No erasure event was ever published in a release, so there
> is no compatibility to keep: a 0.6-draft event (`payload_cid` `none://`) does not count.
> Everything else is unchanged: every block, root, checkpoint, receipt and policy of 0.6-draft
> is valid under 0.7-draft. A 0.6-draft verifier rejects a policy that carries `erasureKey`, as
> an unknown member — correctly, since it would not know what to do with it.

> **0.6-draft adds, and changes nothing that existed**
> ([ADR-031](adr/ADR-031-supresion.md) and its amendment). It registers the erasure event,
> type `nucleo.erasure.v1` (§5.1), reserves the `nucleo.` type prefix, and names the one
> exception to the random-field rule of §5. Every block, root, checkpoint and receipt
> produced under 0.5-draft is valid under 0.6-draft, and a 0.5-draft verifier verifies an
> erasure event like any other block: it is one.

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

> **Amendment 2026-10-10 (Sprint 17): implementation status.** The heading still says
> *"pending implementation"*; it is left as written, and it is stale. Implemented as of
> v0.3.1-alpha: the checkpoint (three body lines, extension lines rejected), the Ed25519 log
> signature (0x01), the additional ML-DSA-44 signature (ADR-007, added to every checkpoint
> the log signs), witness cosignatures with key ID algorithm byte 0x04, the witness protocol
> with transactional persistence (ADR-011, one process for many logs since ADR-030), and the
> receipt as a `tlog-proof` plus its wrapper (§3.1). **Not implemented**: QR codes, and
> archived segments as `tlog-tiles` (§7). The origin line has no imposed scheme: the operator
> chooses it with `nucleo init --origin`, and the example `nucleoledger.com/<tenant-log-id>`
> is only an example. The witness only witnesses logs whose checkpoints have exactly three
> body lines — that is, Núcleo logs; verbatim-preserving parsing for other logs is still
> not implemented. Where each item is tested: `docs/GARANTIAS.md`, §1 and §3.

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
| `erasureKey` | string | OPTIONAL; exactly 64 characters from `[0-9a-f]`; the Ed25519 public key that authorizes erasures (§5.1); MUST differ from `logKey`, from `signerKey` and from every witness key |
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
block (ADR-017). `erasureKey`, when present, MUST differ from the key that signs the blocks
(ADR-032): a policy whose erasure key is a server key authorizes nothing.

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
- **`payload_hash` confirms a guess of the whole document, and the ledger does not hide an
enumerable payload.** The header carries `payload_hash` in clear and the header travels
inside every receipt, so this is not a property of the local file: it is what every
counterparty holding a receipt gets. Whoever can guess the exact bytes can confirm the
guess, encrypted blob or not — the blob protects the content from whoever reads the
database, not from whoever holds the receipt. Field-level commitments (ADR-003) **do not**
cover this case: if the entire document is guessable, its committed fields are guessed
along with it, so per-field protection never raises the bar above the entropy of the whole
document. This is a property of the document, which the protocol does not control, so:
payloads that Núcleo itself constructs (profiles) MUST include a random field of at least
16 bytes —with exactly one exception, the erasure event of §5.1, whose only content is a hash
already public in the chain and which MUST be deterministic to be found—, and payloads supplied by an integrator SHOULD carry equivalent entropy when the
document space is enumerable. A verifier is unaffected: it holds the document and compares
bytes. Núcleo MUST NOT add entropy to a payload it is given — hashing anything other than
the exact bytes received would mean sealing a document the integrator never handed over
([ADR-023](adr/ADR-023-payload-hash-y-enumeracion.md), added 2026-09-18 after the external
audit, H10).
- The ledger stores commitments for the fields a profile declares guessable, and the bare
SHA-256 of the whole payload (above). Sensitive payloads live in **erasable encrypted blobs**: XChaCha20-Poly1305, random 24-byte nonce, `AAD = tenant ‖ payload_hash`. Erasure of blob + key removes the content while the chain stays intact. Whether that
satisfies a particular deletion right is a legal question about a particular regime and a
particular deployment — what remains is the `payload_hash` and the commitments, which are
data about the erased document. The protocol states the technical fact and takes no
position on the legal one (corrected 2026-09-13, fourth audit).

### 5.1 Erasure event (normative, 0.6-draft; authorization 0.7-draft)

Erasing a record's content —its encrypted blob and its commitments— MUST leave a sealed
**erasure event** in the same chain, so that an erased record is distinguishable from one
that disappeared ([ADR-031](adr/ADR-031-supresion.md)); and the event counts only if the
**erasure key** of the verification policy authorized it
([ADR-032](adr/ADR-032-autoridad-de-supresion.md)).

- It is an ordinary block (§1). Its `type` is `nucleo.erasure.v1`; its `tenant` is the tenant
  of the erased block; its `payload_cid` carries the authorization (below) — the payload is
  not stored, because it can be rebuilt.
- Its payload is the JCS (RFC 8785) serialization of exactly one member:
  `{"erased_payload_hash":"<h>"}`, where `<h>` is the erased `payload_hash` as 64 lower-case
  hex characters. Nothing else: no reason, no requester, no index — any of those may itself
  be personal data. Test vector, computed outside the implementation with `sha256sum`: for
  `<h>` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`, the payload is
  90 bytes and its `payload_hash` is
  `1de24cf3e82d924ec8cb94c7d56af49adcb8776cd45b32a2e9d29b5c7053a737`.
- It carries **no random field**, by exception to §5: its only content is a hash that is
  already public in the chain, so guessing it reveals nothing, and determinism is what lets a
  verifier find it.
- The `nucleo.` type prefix is **reserved** for events Núcleo seals itself. An implementation
  MUST NOT let an integrator seal a record with a type under it. This is a guardrail, not the
  boundary: whoever holds the tenant key can seal any block, and that is why an event counts
  only with the authorization below.

**The authorization.** The holder of the erasure key — whose public key is the policy's
`erasureKey` (§3.2), and whose private key MUST NOT be derivable from the passphrase, the KEK or
the vault's backup shares — signs this exact text, UTF-8, every line ending in `\n`:

```
nucleo.org/erasure-authorization@v1
origin <origin>
erased_payload_hash <h>
through <k>
```

where `<origin>` is the log's origin, `<h>` the erased `payload_hash` (64 lower-case hex) and
`<k>` a block index in decimal, matching `0|[1-9][0-9]*` and at most 2^53 − 1. The signature is
`Ed25519(erasure_sk, SHA-256(text))` — the digest is signed, as for blocks (§1). The text is
unambiguous even if the origin contained a line feed: its last two lines have a fixed form.
The authorization covers the blocks with content `<h>` whose index is **at most `<k>`**: a copy
of the same content sealed later is a new record, and an old authorization does not erase it.

It travels in the event's `payload_cid`, exactly:

```
nucleo-erasure-auth@v1:<k>:<signature as 128 lower-case hex characters>
```

The header — and so `payload_cid` — is signed by the tenant, committed by the leaf and carried
whole by every receipt (§3.1); the payload is not. That is why the signature is here.

**When an event is authorized.** Given a policy with `origin` and `erasureKey`, an event `E` is
authorized if and only if (1) its `payload_cid` has the form above with `<k>` < `E.index`;
(2) some block before `E` has a `payload_hash` `<h>` with `E.payload_hash` = SHA-256 of the
erasure payload for `<h>`; and (3) the signature verifies under `erasureKey` over the text built
from the policy's `origin`, `<h>` and `<k>`. Without a policy, or with a policy without
`erasureKey`, no event is authorized.

**When a block counts as erased.** A block `B` counts as erased if and only if there is an
authorized event for `B.payload_hash` with `B.index` ≤ `<k>`. Since `<k>` < `E.index`, the event
is later than `B`; an earlier event erased an earlier copy, which `B` sealed again. A
reconciliation MUST report every event that is not authorized as an integrity finding, and the
block it claimed to erase as missing. Erasure events are Núcleo's own blocks, not records of
the live system.

Test vector, computed outside the implementation with Python's `cryptography` and checked with
OpenSSL 3 (`testdata/vectors/erasure/`): seed `000102…1f` (the 32 bytes 0x00 to 0x1f), public key
`03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8`, origin
`nucleoledger.com/mi-empresa`, `<h>` as in the payload vector above and `<k>` = 7: the text is
166 bytes, its SHA-256 is `24dc174105ced3274e000da312e198508f1f6aa283f0394f99afad3cf76cc7b7`, and
the signature is
`47eaf6d83b72696fa1e7001b41ad249c94b68548607fd8b97e855a19c6d785306c1e2aa0e75b1bf2e018924be20f6fd8aad5ad6796f74e3e38035252cd00ac07`.

**A third party, without Núcleo.** With the receipt of the event, the receipt of the erased
block and the policy: verify both receipts; check that the block's `index` ≤ `<k>` < the event's
index and that the event's `payload_hash` is the SHA-256 of
`{"erased_payload_hash":"<the block's payload_hash>"}`; then verify the signature:

```
printf 'nucleo.org/erasure-authorization@v1\norigin %s\nerased_payload_hash %s\nthrough %s\n' \
  "$ORIGIN" "$H" "$K" | sha256sum | cut -d' ' -f1 | xxd -r -p > digest.bin
(printf '302a300506032b6570032100'; printf %s "$ERASURE_KEY") | xxd -r -p \
  | openssl pkey -pubin -inform DER -out erasure.pem
printf %s "$SIG" | xxd -r -p > sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey erasure.pem -in digest.bin -sigfile sig.bin
```

## 6. Keys (normative, pending implementation)

- Signing identity: Ed25519 per tenant.
- At-rest hierarchy: passphrase → Argon2id → **KEK**; random 32-byte **DEK** per vault, wrapped by KEK.
- Backup: **SLIP-0039** mnemonic shares protecting the KEK, default threshold 2-of-3 (3-of-5 for multi-partner orgs). Guided backup UX is a v1 requirement.
- Identity rotation: a special block type signed by the outgoing key authorizing the new key. If the old key is lost: new identity anchored via witnesses + an out-of-band partner attestation; the discontinuity MUST be visible in the chain.

> **Amendment 2026-10-10 (Sprint 17): implementation status.** The heading's *"pending
> implementation"* is left as written; it is half stale. Implemented: the at-rest
> hierarchy (passphrase → Argon2id → KEK → DEK) and the SLIP-0039 backup of the KEK, 2-of-3
> by default (`--shares` and `--threshold` allow 3-of-5), with the guided, typed
> confirmation (ADR-004, ADR-010); a new passphrase from the cards (ADR-029). **Not as
> written**: the signing identity is **one Ed25519 key per vault**, not per tenant — the
> tenants of a ledger share the block-signing key, and the log has its own key for
> checkpoints. **Not implemented**: identity rotation, in either form. Today a lost or
> compromised key means a new log, and the old one is retired at its witnesses
> (ADR-029, amendment §F; ADR-030 §C).

## 7. Segments (normative, pending implementation)

Periods (monthly or yearly by volume) close with a witnessed checkpoint. Historical segments are archived as static tiles. Cross-segment verification uses RFC 9162 consistency proofs between closing checkpoints (Rekor-v2-style sharding).

## 8. Storage (normative)

SQLite, pure-Go driver, WAL, `synchronous=FULL`, single writer. The blocks table MUST carry BEFORE UPDATE/DELETE triggers that abort. Triggers are a guardrail, not the security boundary — witnesses are.

## 9. Deployment modes

1. **CLI (primary)**: `nucleo seal|verify|...` invocable per execution (shared-hosting compatible).
2. **Daemon (optional)**: localhost HTTP / Unix socket, OpenAPI-described; thin clients per language (TS → PHP → Python → Java).
3. **Go module**: direct import for Go integrators.

> **Amendment 2026-10-10 (Sprint 17): implementation status.** Only mode 1 exists. The
> daemon of mode 2 does not exist and is **not planned for v1** (amendment to CONCEPTO,
> Sprint 15; ADR-005 and its amendment), so there is no OpenAPI description either. The thin
> clients exist without it: `@nucleoledger/verify` (TypeScript, verification only) and the
> PHP SDK (native verifier, and a sealer that wraps the CLI binary, ADR-021). Mode 3 does not
> exist as written: every Go package lives under `internal/`, which Go forbids importing from
> another module, so a Go integrator calls the CLI like everyone else. Exposing a public Go
> API would be a decision of its own, with its ADR.

## 10. Out of scope of the protocol

Legal validity claims, truth of original content, and protection against an adversary who controls keys, ledger, and all witnesses with no receipts issued. Documentation language: "designed to align with" LOPDP / ISO 27001 / ISO 27037 — never "certified" without formal backing.
