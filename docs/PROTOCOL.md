# Núcleo Protocol Specification

**Version: 0.1-draft (decisions frozen 2026-08-31; wire formats stabilize at v1.0)**

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
- Chain rules: `index` consecutive, `prev_hash` matches, timestamps non-decreasing, and full-chain verification MUST enforce an expected signer key.

## 2. Merkle tree (implemented)

RFC 6962 with SHA-256: leaf hash = `SHA-256(0x00 ‖ data)`, node = `SHA-256(0x01 ‖ l ‖ r)`. Leaves are block hashes (raw 32 bytes). Inclusion proofs verified per RFC 9162 §2.1.3.2. Consistency proofs (RFC 9162 §2.1.4) are implemented. Domain extension: for oldSize == newSize the proof MUST be empty and verification additionally requires byte-equality of the two 32-byte roots; the RFC defines proofs only for 0 < m < n, so any cross-language implementation MUST adopt this same convention to stay interoperable. Proof nodes have no bespoke wire format: they serialize as one base64 (RFC 4648 §4) hash per line, exactly as consumed by c2sp.org/tlog-proof; the in-memory [][]byte representation is not a wire format. Both roots MUST be exactly 32 bytes; verification fails closed otherwise.

## 3. C2SP artifacts (normative, pending implementation)

Núcleo is a C2SP-compatible log. Pinned specs (record exact versions in ADR-001 when implemented):

- **Checkpoint**: `c2sp.org/tlog-checkpoint` — signed note with origin line, tree size, root hash. A log MUST NOT sign a checkpoint inconsistent with any previously signed one. Origin line: `nucleoledger.com/<tenant-log-id>` (final scheme fixed at first release). Núcleo emits exactly three body lines; the parser currently rejects extension lines (fail closed). Verbatim-preserving parsing is required before witnessing third-party logs.
- **Log signature**: Ed25519 signed-note signature (type 0x01) REQUIRED. Key ID algorithm bytes are distinct per role and enter the key ID hash: log signature: signed-note type 0x01; witness cosignatures: c2sp.org/tlog-cosignature@v1 with key ID algorithm byte 0x04 (0x06 reserved for future ML-DSA-44 cosignatures). An additional **ML-DSA-44** cosignature-style signature SHOULD be added (verifiers ignore unknown signatures, so this is backward-compatible).
- **Witness cosignatures**: `c2sp.org/tlog-cosignature@v1` (72-byte timestamped_signature). Witness protocol: `c2sp.org/tlog-witness` — the witness MUST persist the new checkpoint atomically with the consistency check before responding (rollback-race prevention).
- **Receipt / proof bundle**: `c2sp.org/tlog-proof` — self-contained offline-verifiable proof (checkpoint + cosignatures + index + inclusion proof + extra data). The Núcleo *receipt* IS a tlog-proof plus a human-readable wrapper. QR codes carry a URL to the static verifier + the entry hash, NOT the full proof.
- **Archived segments**: `c2sp.org/tlog-tiles` static tiles.

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
