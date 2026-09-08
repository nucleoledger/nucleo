# @nucleoledger/verify

Offline verifier for [Núcleo](https://github.com/nucleoledger/nucleo) receipts.

A Núcleo receipt proves that a specific record was in a transparency log at a
specific time. This package checks that proof — **without contacting the issuer,
their server, or anything else**. It works in a browser tab with the network
disconnected.

**Zero runtime dependencies.** Ed25519 and SHA-256 come from WebCrypto, which is
part of the platform. Nothing else is needed.

```bash
npm install @nucleoledger/verify
```

## Requirements

An environment with **Ed25519 in WebCrypto**: Node ≥ 20, Chrome ≥ 137,
Safari ≥ 17, Firefox ≥ 130. In a browser the page must be served over `https` or
from `localhost`, because `crypto.subtle` is unavailable otherwise.

## Usage

```ts
import { verifyReceipt } from "@nucleoledger/verify";

const result = await verifyReceipt(receiptText, {
  origin: "example.com/my-company",
  logKey: "9ad2d5b3…",                       // hex, 32 bytes
  witnesses: { "witness.example/w1": "dd7e84d0…" },
  quorum: 1,
});

if (!result.valid) {
  console.error("invalid receipt:", result.reasons);
} else {
  console.log("record", result.blockIndex, "was in the log");
  console.log("declared:", result.declaredTime);   // the issuer's clock
  console.log("provable:", result.provableTime);   // a witness's clock
}
```

In the browser it is the same call:

```html
<script type="module">
  import { verifyReceipt } from "https://esm.sh/@nucleoledger/verify";
  const result = await verifyReceipt(await file.text(), policy);
</script>
```

Or, with no bundler and no CDN, bundle it once and load a single file — that is
what [`web/verify/index.html`](https://github.com/nucleoledger/nucleo/tree/main/web/verify)
does.

## The two clocks

`verifyReceipt` returns both and never conflates them, because they answer
different questions:

- **`declaredTime`** is the timestamp the issuer put in the record. It comes from
  a clock they control, so **it can lie**. It is returned because it is useful,
  not because it proves anything.
- **`provableTime`** is the earliest timestamp among the witness cosignatures
  that verify **under the policy you passed**. An independent third party stated
  it saw that tree at that moment.

If no witness in your policy signed it, `provableTime` is `null`. That is not a
degraded result: it means the receipt proves *that* the record is in the log, not
*when* it existed.

## Why `bigint`

`blockIndex` and the checkpoint size are `bigint`, and the whole inclusion-proof
loop runs in `bigint`. That is not fastidiousness.

JavaScript's bitwise operators coerce their operands to **32-bit signed**
integers, and `number` is a double, exact only up to 2⁵³. A transparency log has
no reason to stop below two billion entries, and on the day one does not, an
implementation using `>>` and `Number` would compute a different index — silently,
with no exception and no warning, which is the worst possible failure mode for a
verifier.

There is not a single bitwise operator left in this package, and the test suite
enforces that with a grep.

The practical consequence: `JSON.stringify(result)` throws on a `bigint`. Convert
with `String(result.blockIndex)` when serializing. Inconvenient, but honest.

## It never throws

`verifyReceipt` returns `{ valid: false, reasons: [...] }` instead of raising.
A verifier that throws forces every caller into a `try`, and one forgotten `try`
turns a bad receipt into a good one.

```ts
interface Result {
  valid: boolean;
  declaredTime: string | null;
  provableTime: string | null;
  blockIndex: bigint | null;   // bigint: a tree index can exceed 2^53
  recipient: string | null;
  cosigners: string[];
  ignoredSignatures: string[];
  reasons: string[];        // in Spanish, meant to be shown to a person
  checkpoint: { origin: string; size: string; rootHash: string } | null;
}
```

## What gets checked

1. The receipt parses and its header is in canonical form.
2. The checkpoint is signed by the log key in your policy.
3. Cosignatures verify against the witness keys in your policy, and the quorum is
   met.
4. The RFC 9162 inclusion path leads from the record to the checkpoint root.
5. **The human-readable header matches the proof, byte for byte.** A receipt with
   a flawless proof and a doctored visible text is rejected. This one matters:
   the text is what a person reads.

## Signatures it ignores

A signed note can carry signatures from keys this verifier does not know — the
log's ML-DSA-44 signature, cosignatures from other witnesses. **They are ignored**,
as `c2sp.org/signed-note` requires. That is what lets one receipt circulate
between parties who trust different witnesses.

What is *not* ignored is a signature from a key you **do** know that fails to
verify. That invalidates the whole receipt.

## Test vectors

The test suite reads the same files under
[`testdata/vectors/`](https://github.com/nucleoledger/nucleo/tree/main/testdata/vectors)
as the Go implementation — the official RFC 6962 Merkle vectors, the RFC 8785 key
ordering cases, and three golden receipts generated by the Go code. Not a copy:
the same files. Shared vectors that are not shared verify nothing.

That is how a real bug was caught: this verifier treated a block hash as an
already-computed Merkle leaf, while Go treats it as leaf *data* and applies the
`0x00` domain prefix itself. Two conventions, two different roots for the same
tree.

## License

AGPL-3.0-or-later. Commercial licenses are available for embedding Núcleo in
proprietary software.
