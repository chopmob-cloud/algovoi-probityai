"""Build the refund / receipt-binding conformance vectors, then run the
offline verifier over them and check every verdict against expectation.

Run:  python demo.py          # build vectors, verify, print the table
      python demo.py --write  # also (re)write vectors/*.json fixtures

Exit code is non-zero if any vector's verdict does not match expectation, so
this doubles as the local validation harness.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from offline_verifier import (
    Axis,
    Overall,
    Result,
    canonical_bytes,
    digest,
    verify,
)

HERE = os.path.dirname(os.path.abspath(__file__))
VECTOR_DIR = os.path.join(HERE, "vectors")

# A fixed seed so the issuer key, and therefore every fixture digest and
# signature, is byte reproducible across machines and runs.
ISSUER_SEED = bytes.fromhex(
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
)


def sign_receipt(sk: Ed25519PrivateKey, receipt: dict) -> dict:
    """Sign a receipt over its canonical form minus the sig field."""
    unsigned = {k: v for k, v in receipt.items() if k != "sig"}
    receipt = dict(receipt)
    receipt["sig"] = sk.sign(canonical_bytes(unsigned)).hex()
    return receipt


def build_vectors(sk: Ed25519PrivateKey):
    """Return a list of (name, expectation, request, effect, receipt)."""
    attacker = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)

    def base_request():
        return {
            "op_id": "op-A",
            "action": "refund",
            "amount": "12.50",
            "currency": "USD",
            "payee": "acct:alice",
            "nonce": "req-nonce-01",
            "expiry": "2026-10-29T12:00:00Z",
        }

    def effect(**over):
        e = {
            "op_id": "op-A",
            "status": "committed",
            "amount": "12.50",
            "currency": "USD",
            "payee": "acct:alice",
            "balance_before": "100.00",
            "balance_after": "112.50",
            "applied_count": 1,
            "observed_at": "2026-10-29T11:00:00Z",
        }
        e.update(over)
        return e

    def receipt_for(req, eff, nonce="rcpt-01"):
        return {
            "op_id": req["op_id"],
            "request_digest": digest(req),
            "effect_digest": digest(eff),
            "nonce": nonce,
            "issued_at": "2026-10-29T11:00:01Z",
        }

    vectors = []

    # V1 clean refund: approved, committed, bound, applied once, so ACCEPT.
    req = base_request()
    eff = effect()
    vectors.append((
        "v1-clean-refund",
        {"overall": Overall.ACCEPT, "primary": None},
        req, eff, sign_receipt(sk, receipt_for(req, eff)),
    ))

    # V2 committed but unacknowledged: effect real, no completion ack.
    # Neither success nor failure, so UNCONFIRMED on completion only.
    req = base_request()
    eff = effect(status="interrupted")
    vectors.append((
        "v2-interrupted-unconfirmed",
        {"overall": Overall.UNCONFIRMED, "primary": (Axis.COMPLETION, Result.UNCONFIRMED)},
        req, eff, sign_receipt(sk, receipt_for(req, eff)),
    ))

    # V3 double apply on retry: applied twice, ledger moved 2x.
    # Amount stays internally consistent (12.50 x 2); idempotency fails, so REJECT.
    req = base_request()
    eff = effect(applied_count=2, balance_after="125.00")
    vectors.append((
        "v3-double-apply",
        {"overall": Overall.REJECT, "primary": (Axis.IDEMPOTENCY, Result.FAIL)},
        req, eff, sign_receipt(sk, receipt_for(req, eff)),
    ))

    # V4 amount mismatch: effect moved 20.00, approval was 12.50, so REJECT.
    req = base_request()
    eff = effect(amount="20.00", balance_after="120.00")
    vectors.append((
        "v4-amount-mismatch",
        {"overall": Overall.REJECT, "primary": (Axis.AMOUNT_CONSISTENCY, Result.FAIL)},
        req, eff, sign_receipt(sk, receipt_for(req, eff)),
    ))

    # V5 saved success outlives real state: the receipt pins an effect
    # snapshot; the reader's fresh read differs only in observed_at, so the
    # receipt no longer describes what is there, effect_binding fails, so REJECT.
    req = base_request()
    receipted_eff = effect()                              # snapshot the receipt covers
    observed_now = effect(observed_at="2026-10-29T18:30:00Z")  # fresh read, later
    vectors.append((
        "v5-stale-effect-binding",
        {"overall": Overall.REJECT, "primary": (Axis.EFFECT_BINDING, Result.FAIL)},
        req, observed_now, sign_receipt(sk, receipt_for(req, receipted_eff)),
    ))

    # V6 forged receipt: signed by an attacker key, not the pinned issuer.
    # Signature fails; bindings cannot be trusted, so REJECT.
    req = base_request()
    eff = effect()
    vectors.append((
        "v6-forged-receipt",
        {"overall": Overall.REJECT, "primary": (Axis.RECEIPT_SIGNATURE, Result.FAIL)},
        req, eff, sign_receipt(attacker, receipt_for(req, eff)),
    ))

    # V7 failed status must not be certified: a signed receipt binding a
    # status=failed effect (claiming one application but moving no money) must
    # never ACCEPT. The verifier certifies realised effects only, so completion
    # fails closed and the overall verdict is REJECT.
    req = base_request()
    eff = effect(status="failed", balance_after="100.00")
    vectors.append((
        "v7-failed-not-certified",
        {"overall": Overall.REJECT, "primary": (Axis.COMPLETION, Result.FAIL)},
        req, eff, sign_receipt(sk, receipt_for(req, eff)),
    ))

    # V8 operation identity: the receipt validly binds the approved request and
    # a financially identical effect, but the effect names a different operation
    # (op-B). A digest check alone would pass; the operation identity check in
    # the binding axis catches it, so the overall verdict is REJECT. This closes
    # the pairing of an approval for one operation with the effect of another.
    req = base_request()
    eff = effect(op_id="op-B")
    vectors.append((
        "v8-operation-identity",
        {"overall": Overall.REJECT, "primary": (Axis.EFFECT_BINDING, Result.FAIL)},
        req, eff, sign_receipt(sk, receipt_for(req, eff)),
    ))

    return vectors


def write_fixtures(pub: Ed25519PublicKey, vectors):
    os.makedirs(VECTOR_DIR, exist_ok=True)
    # newline="\n" forces LF on every platform so published fixtures are byte
    # identical whether generated on Windows or Linux.
    with open(os.path.join(VECTOR_DIR, "issuer_pubkey.hex"), "w",
              encoding="utf-8", newline="\n") as f:
        from cryptography.hazmat.primitives import serialization
        raw = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        f.write(raw.hex() + "\n")
    for name, exp, req, eff, rcpt in vectors:
        doc = {
            "name": name,
            "expected": {
                "overall": exp["overall"].value,
                "primary_axis": exp["primary"][0].value if exp["primary"] else None,
            },
            "approved_request": req,
            "observed_effect": eff,
            "receipt": rcpt,
        }
        path = os.path.join(VECTOR_DIR, f"{name}.json")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
            f.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="(re)write JSON fixtures")
    args = ap.parse_args()

    sk = Ed25519PrivateKey.from_private_bytes(ISSUER_SEED)
    pub = sk.public_key()
    vectors = build_vectors(sk)

    if args.write:
        write_fixtures(pub, vectors)
        print(f"wrote {len(vectors)} fixtures to {VECTOR_DIR}\n")

    width = max(len(n) for n, *_ in vectors)
    header = f"{'vector':<{width}}  {'verdict':<12}  reason"
    print(header)
    print("-" * len(header))

    ok = True
    for name, exp, req, eff, rcpt in vectors:
        verdict = verify(req, eff, rcpt, pub)

        # overall must match
        overall_ok = verdict.overall == exp["overall"]

        # the named primary axis must carry its expected result
        primary_ok = True
        reason = ""
        if exp["primary"]:
            axis, want = exp["primary"]
            got = verdict.by_axis(axis)
            primary_ok = got.result == want
            reason = f"{axis.value}={got.result.value}: {got.detail}"
        else:
            reason = "all axes PASS"

        row_ok = overall_ok and primary_ok
        ok = ok and row_ok
        mark = "" if row_ok else "  <<< MISMATCH"
        print(f"{name:<{width}}  {verdict.overall.value:<12}  {reason}{mark}")

    print()
    if ok:
        print("ALL VECTORS MATCH EXPECTATION")
        return 0
    print("ONE OR MORE VECTORS DID NOT MATCH EXPECTATION")
    return 1


if __name__ == "__main__":
    sys.exit(main())
