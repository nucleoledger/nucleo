# Security Policy

## Reporting a vulnerability

**Please do not open a public issue.**

Use one of these, in order of preference:

1. **GitHub private vulnerability reporting** — the *Report a vulnerability*
   button under the [Security tab](https://github.com/nucleoledger/nucleo/security).
   It creates a private thread with the maintainers and needs no email.
2. **security@nucleoledger.com**, if you prefer email.

Please include:

- what you found and why it matters,
- steps or a minimal case to reproduce it,
- the version or commit you tested,
- and, if you have one, how you would fix it.

## What to expect

- **Acknowledgement within 72 hours.** If you do not hear back, assume the
  message got lost and try the other channel.
- An assessment within a week, saying whether we consider it a vulnerability and
  why.
- Credit in the release notes and in the ADR that records the fix, unless you
  prefer otherwise.

This is a small project without a security team. What we can promise is that
reports get read by someone who understands the code, and that findings get
fixed with the reasoning written down rather than patched in silence.

## Scope

**In scope:** anything that lets a record be altered, removed or backdated
without detection; anything that reveals a committed value without the key;
anything that makes a receipt verify when it should not, or fail when it should
not; key handling; and the release pipeline.

**Out of scope**, because they are documented properties rather than defects:

- **A file cannot testify about its own completeness.** Whoever controls the
  ledger file can truncate it, and no check living inside that file can prove
  otherwise. That is what witnesses are for, and it is written up in
  [ADR-009](docs/adr/ADR-009-store-schema.md).
- **A block's signature is not inside its Merkle leaf**, so a cosigned root does
  not pin the `signature` column. `verify --full` catches corruption there.
- **A receipt's recipient is not covered by any signature.** It is chosen at
  issue time, after sealing. The name is an address, not proof.
- **A network adversary can prevent detection** by blocking access to a witness.
  That is availability, it is noisy, and it cannot forge attestation.
- **VRF commitments would not give privacy**, only third-party verifiability.
  See [ADR-003](docs/adr/ADR-003-compromisos-vrf-hmac.md).

If you think one of those "documented properties" is worse than we describe, that
**is** in scope. Being wrong about our own limits is exactly the kind of mistake
worth hearing about.

## Supported versions

While the major version is `0`, only the latest release gets fixes.

## No external audit yet

No professional third-party security audit has been performed on this code, and
it has not been used in production by anyone. The reviews that shaped it were
adversarial model-driven audits, documented in the ADRs — thorough, but not the
same thing. Treat the software accordingly.
