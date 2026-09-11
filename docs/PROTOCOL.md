# Núcleo Protocol Specification

**Version: 0.2-draft (decisions frozen 2026-08-31; leaf rule changed 2026-09-10; wire formats stabilize at v1.0)**

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
| `timestamp` | string | RFC 3339 with nanoseconds, MUST be UTC (`Z` suffix), non-decreasing |
| `tenant` | string | Organization identifier (e.g. RUC). Non-empty |
| `type` | string | Record type, e.g. `sri.factura.v1`. Non-empty |
| `payload_hash` | hex(32B) | SHA-256 of the exact payload bytes (see §5) |
| `payload_cid` | string | Reference to the encrypted blob stored outside the log |
| `signer_pubkey` | hex(32B) | Ed25519 public key of the tenant signer |

- `hash = SHA-256( JCS(header) )` where JCS is RFC 8785. Implementations MUST pass the official RFC 8785 test vectors.
- `signature = Ed25519(sk, hash)` — the 32-byte digest is signed, not the JSON, so a verifier holding only hashes can check signatures.
- The signature MUST be deterministic. Ed25519 (RFC 8032) is, and §2.1 depends on it: the leaf commits to the signature bytes, so a signature that varied between runs would change the tree. Any future signature algorithm for blocks MUST use its deterministic variant.
- Chain rules: `index` consecutive, `prev_hash` matches, timestamps non-decreasing, and full-chain verification MUST enforce an expected signer key.

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
a verifier MUST re-render it and require byte equality. It carries the recipient, the
issuer, the record type, the payload hash, the block index, both clocks labelled
separately (§4), and a legal notice. The notice and the recipient label are inside
that byte-equality check on purpose: a receipt with either one removed does not
verify.

Machine section of `receipt@v2`, one item per line, in this order:

```
<JCS(header)>                     canonical header bytes, exactly as signed
<base64(signature)>               the block's 64-byte Ed25519 signature
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

## 4. Time (normative)

- The block `timestamp` is **declared time** (local clock; can lie).
- **Provable time** of an entry = the earliest external attestation covering it: minimum of witness cosignature timestamps, and RFC 3161 TSA tokens if configured.
- Receipts MUST label both values separately. Documentation MUST NOT present declared time as proof.

## 5. Payloads (normative)

- Externally signed documents (SRI XML with XAdES-BES, PDFs) are hashed **byte-for-byte, never re-canonicalized**.
- JSON payloads authored by Núcleo profiles are canonicalized with JCS before hashing. Monetary amounts and identifiers MUST travel as strings.
- Low-entropy / guessable values (IDs, amounts, statuses) MUST NOT be committed as bare hashes. Use a **VRF commitment** (`c2sp.org/vrf-r255`) when third-party verifiability without key disclosure is needed; HMAC-SHA-256 with a tenant secret otherwise. (Pending implementation; format fixed in ADR-003.)
- The ledger stores only commitments. Sensitive payloads live in **erasable encrypted blobs**: XChaCha20-Poly1305, random 24-byte nonce, `AAD = tenant ‖ payload_hash`. Erasure of blob + key satisfies data-deletion rights while the chain stays intact.

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
