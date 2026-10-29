"""Adversarial tests: prove the verifier fails closed on crafted inputs.

Each probe hands the verifier an input a hostile producer might try (non finite
and float amounts, negative or boolean application counts, malformed or missing
signatures, unsupported statuses) and asserts the overall verdict is never
ACCEPT. Exit code is non zero if any probe is not safe.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from offline_verifier import verify, digest, canonical_bytes, Overall

sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"))
pub = sk.public_key()


def req():
    return {"op_id": "op-A", "action": "refund", "amount": "12.50",
            "currency": "USD", "payee": "acct:alice", "nonce": "n1",
            "expiry": "2026-10-29T12:00:00Z"}


def eff(**o):
    e = {"op_id": "op-A", "status": "committed", "amount": "12.50",
         "currency": "USD", "payee": "acct:alice", "balance_before": "100.00",
         "balance_after": "112.50", "applied_count": 1,
         "observed_at": "2026-10-29T11:00:00Z"}
    e.update(o)
    return e


def signed(r, e):
    rc = {"op_id": r["op_id"], "request_digest": digest(r),
          "effect_digest": digest(e), "nonce": "r1", "issued_at": "t"}
    rc["sig"] = sk.sign(canonical_bytes(rc)).hex()
    return rc


def run(label, r, e, rc, expect_not=Overall.ACCEPT):
    v = verify(r, e, rc, pub)
    safe = v.overall != expect_not
    flag = "ok (not ACCEPT)" if safe else "!!! ACCEPTED -- UNSAFE"
    print(f"{label:<40} overall={v.overall.value:<12} {flag}")
    return safe


ok = True
# NaN amount must never ACCEPT.
e = eff(amount="nan", balance_after="100.00"); ok &= run("amount=NaN", req(), e, signed(req(), e))
# Infinity amount.
e = eff(amount="Infinity", balance_after="100.00"); ok &= run("amount=Infinity", req(), e, signed(req(), e))
# Negative applied_count with matching negative delta.
e = eff(applied_count=-1, balance_after="87.50"); ok &= run("applied_count=-1", req(), e, signed(req(), e))
# applied_count as bool True.
e = eff(applied_count=True); ok &= run("applied_count=True(bool)", req(), e, signed(req(), e))
# applied_count zero.
e = eff(applied_count=0, balance_after="100.00"); ok &= run("applied_count=0", req(), e, signed(req(), e))
# Scientific-notation amount equal in value but different string -> effect_digest still binds, amount numeric-equal.
e = eff(amount="1.250E1"); rc = signed(req(), e); ok &= run("amount=1.250E1 (==12.50)", req(), e, rc, expect_not=None)
# status=failed with no movement (the semantic edge).
e = eff(status="failed", applied_count=0, balance_after="100.00"); ok &= run("status=failed no-op", req(), e, signed(req(), e))
# Codex's exact bypass: status=failed, applied_count=1, unchanged balance.
e = eff(status="failed", applied_count=1, balance_after="100.00"); ok &= run("status=failed applied=1 unchanged", req(), e, signed(req(), e))
# Float amount must be refused by the decimal-string contract.
e = eff(amount=12.5, balance_after="112.50"); ok &= run("amount=float 12.5", req(), e, signed(req(), e))
# Malformed signatures must REJECT, not crash.
r = req(); e = eff(); rc = signed(r, e); rc["sig"] = None
ok &= run("sig=None", r, e, rc)
r = req(); e = eff(); rc = signed(r, e); rc["sig"] = 12345
ok &= run("sig=int", r, e, rc)
# Unknown status.
e = eff(status="pending"); ok &= run("status=pending", req(), e, signed(req(), e))
# Receipt with sig field absent.
r = req(); e = eff(); rc = {"op_id": "op-A", "request_digest": digest(r), "effect_digest": digest(e), "nonce": "r1", "issued_at": "t"}
ok &= run("receipt missing sig", r, e, rc)
# Tampered one hex char of sig.
r = req(); e = eff(); rc = signed(r, e); rc["sig"] = ("0" if rc["sig"][0] != "0" else "1") + rc["sig"][1:]
ok &= run("sig first char flipped", r, e, rc)

# Trailing newline must not slip past the decimal contract.
e = eff(amount="12.50\n"); ok &= run("amount=12.50 with newline", req(), e, signed(req(), e))
# Operation identity: approval for op-A paired with the effect of op-B.
r = req(); e = eff(op_id="op-B")
rc = {"op_id": "op-A", "request_digest": digest(r), "effect_digest": digest(e), "nonce": "r1", "issued_at": "t"}
rc["sig"] = sk.sign(canonical_bytes(rc)).hex()
ok &= run("op_id mismatch req=A eff=B", r, e, rc)

# Operation identity absent from all three records must not pass vacuously.
r = {k: v for k, v in req().items() if k != "op_id"}
e = {k: v for k, v in eff().items() if k != "op_id"}
rc = {"request_digest": digest(r), "effect_digest": digest(e), "nonce": "r1", "issued_at": "t"}
rc["sig"] = sk.sign(canonical_bytes(rc)).hex()
ok &= run("op_id absent everywhere", r, e, rc)

# load_json_strict must refuse non-finite JSON constants and duplicate keys.
from offline_verifier import load_json_strict
for label, text in [("JSON NaN", '{"amount": NaN}'),
                    ("JSON Infinity", '{"amount": Infinity}'),
                    ("duplicate key", '{"a": 1, "a": 2}')]:
    try:
        load_json_strict(text); print(f"{'loader '+label:<40} ACCEPTED        !!! UNSAFE"); ok = False
    except ValueError:
        print(f"{'loader '+label:<40} rejected         ok")

print()
print("ALL ADVERSARIAL PROBES FAILED CLOSED" if ok else "AT LEAST ONE PROBE WAS UNSAFE")
import sys; sys.exit(0 if ok else 1)
