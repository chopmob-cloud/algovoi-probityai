AlgoVoi offline verifier: refund and receipt binding

This is a working check, not a proposal. It takes three records that any reader
can obtain for themselves, an approved request, what the system actually shows
afterwards, and a signed receipt, and decides offline whether the effect that
happened is the effect that was approved. There is no network call and no trust
in the producer beyond one pinned issuer key. Clone it, run one command, and
keep the parts that are useful in your own tests.

THE QUESTION IT ANSWERS

A refund commits but the acknowledgement is lost. A saved success response
outlives the state it described. A retry applies the same refund twice. Two
readers disagree about the same evidence. In each case the honest question is
the same: does the approved request match what actually changed, and is the
receipt really bound to both. A producer maintained self check cannot answer
this for a sceptical reader, because it is the producer's own word. An offline
verifier can, because it recomputes everything from the records and the pinned
key.

WHAT IT CHECKS

The verifier reports a result on each of six axes and then a single verdict.
First, the receipt signature must verify against the pinned issuer key, because
a receipt whose signature does not verify lends nothing to the digests inside
it. Second and third, the request and effect bindings must hold: the receipt
must carry the SHA-256 of the canonical approved request and of the canonical
observed effect, and must name the same operation as both, so it refers to this
request and this effect and not to some other, and cannot pair an approval for
one operation with the effect of another. Fourth, amounts must be consistent: the approved amount must equal the
effect amount, the currency must match, and the balance must have moved by
exactly the amount times the number of applications. Fifth, idempotency: the
operation must have been applied exactly once. Sixth, completion, which is the
crux and is deliberately not a yes or no.

THE THREE OUTCOMES

The overall verdict is ACCEPT, REJECT, or UNCONFIRMED. A refund that commits in
the ledger while its acknowledgement is lost is neither a success nor a failure,
and a verifier that forces it into one is lying. This one returns UNCONFIRMED
and names exactly what is missing, the completion acknowledgement, while still
confirming that the effect itself is present and bound. Any hard axis failing is
a REJECT with the failing axis named. Everything consistent and acknowledged is
an ACCEPT. The check certifies realised effects only: a status it does not model
fails closed rather than being waved through.

THE VECTORS

The vectors directory holds eight byte pinned cases, each a small JSON file you
can read. One is a clean refund that is ACCEPTed. One is the interrupted refund
that is UNCONFIRMED. Six are REJECTed, and each isolates a single defect: a
double application, an amount mismatch, a receipt whose effect binding no longer
matches a fresh read, a receipt signed by the wrong key, a failed status that
must never be certified, and a receipt that binds an approval for one operation
to the effect of another. Every fixture carries its own expected verdict, so the
harness checks itself.

RUNNING IT

```bash
python demo.py
```

That rebuilds the vectors in memory, runs the verifier over all seven, and
prints a table with the verdict and the reason for each. Add --write to also
write the JSON fixtures. The exit code is non zero if any verdict does not match
expectation, so it drops straight into continuous integration. An adversarial
probe, probe_adversarial.py, runs crafted inputs (non finite and float amounts,
negative and boolean application counts, malformed signatures, unsupported
statuses) and asserts every one fails closed.

REPRODUCING THE BYTES

A conformance vector is only useful if a second implementer can reproduce it
exactly. The canonical form is JSON with keys sorted by Unicode code point,
compact separators with no insignificant whitespace, UTF-8 with non ASCII
emitted literally rather than escaped, and non finite floats refused rather than
emitted as the non standard NaN or Infinity tokens. No Unicode normalisation is
applied. Monetary amounts are decimal strings, never floats, so the number
canonicalisation hazard never arises. The fixtures were generated on Windows
with Python 3.12 and on Linux with Python 3.11 and were verified byte for byte
identical. The signatures are Ed25519 over the canonical receipt with its
signature field removed.

SCOPE

The verifier says whether an approved effect occurred as approved and whether
the receipt binds the two. It does not say whether the approved action was
itself a good idea, and the issuer key here is a fixed test key for
reproducibility, not a production key. Treat the match as evidence that the
effect came from the request that was approved, nothing more.

LICENCE

Apache-2.0. Reuse with credit is welcome.
