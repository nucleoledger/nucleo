# Contributing to Núcleo

Thanks for looking. This project is young and the fastest way to help right now
is probably not a pull request.

## Issues before pull requests, for now

The protocol is frozen but the implementation is moving, and several parts are
waiting on decisions recorded as open ADRs. A pull request against a piece that
is about to change is work thrown away — yours and the reviewer's.

**Open an issue first.** Describe what you hit or what you would change. If it is
a bug, that is already the most valuable contribution: a reproducible case beats
a patch you had to guess at.

Small, obvious fixes — a typo, a broken link, a wrong error message — go straight
to a pull request without asking.

## Running the tests

```bash
go test ./... -race                      # must be green
go test -tags testhooks ./... -race      # and so must this
golangci-lint run ./...                  # must report 0 issues
```

### The `testhooks` build tag

CLI tests compare output byte for byte, which needs a fixed clock and a fixed
seed. That code lives behind `//go:build testhooks` and **is not compiled into a
released binary**. Without the tag, a binary that finds `NUCLEO_TEST_SEED` in its
environment refuses to run rather than warning: someone who sets it expects
deterministic keys, and a warning on stderr would leave them believing they got
them.

If you touch anything under `cmd/nucleo`, run the suite **both ways**.

The TypeScript verifier:

```bash
cd sdk/ts
npm ci
npm run typecheck
npm test
```

And the one that decides whether the project works at all:

```bash
./scripts/demo-criterio-exito.sh
```

That script is the success criterion from `docs/CONCEPTO-v1.2-es.md` §18, made
executable. If it fails, something real is broken.

## Test vectors are ground truth

`testdata/vectors/` holds shared vectors — RFC 6962 Merkle, RFC 8785 JCS, the
official SLIP-0039 vectors, and golden receipts. **Both** the Go implementation
and the TypeScript verifier read those same files.

**If a vector fails, the code is wrong, not the vector.** Changing one requires an
ADR explaining why, and it is close to never the right move.

## The anti-circularity rule

Every golden value — a hash, a key ID, a signature, canonical bytes — must be
computed **outside** the code under test: `sha256sum`, `openssl`, an independent
implementation in another language, a hand calculation.

A test that verifies a function by calling that same function verifies nothing.
This project learned it the hard way: a key ID that used the wrong algorithm byte
passed the whole suite, because the test computed the expected value with the
function it was checking.

If you add a golden, say in a comment **which tool produced it**.

## Architecture decisions

Anything that changes a format, a dependency or a security property needs an ADR
in `docs/adr/`. Look at the existing ones for the shape — especially the
amendments, where a measurement contradicted an earlier assumption and the
record says so instead of quietly rewriting history.

New dependencies are a decision, not a detail. `sdk/ts` has **zero** runtime
dependencies and that is a property worth defending.

## Style

- Go code is formatted with `gofmt`. CI enforces it.
- **Identifiers in English, comments in Spanish.** That is the existing
  convention and mixing it makes the codebase harder to read, not easier.
- Comments explain *why*, not *what*. The code already says what it does.
- Commit messages: a short imperative subject line, then the reasoning. If a
  decision was not obvious, the commit is where it gets explained.

## Security

Do **not** open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md).

## License

Contributions are accepted under AGPL-3.0-or-later, the project's license. By
opening a pull request you confirm you have the right to contribute the code
under those terms.
