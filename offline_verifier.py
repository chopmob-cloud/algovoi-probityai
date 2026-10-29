"""Offline verifier for the refund / receipt-binding case.

Given three records that any reader can obtain independently:

  * approved_request  - what the operator approved (the mandate)
  * observed_effect   - what the system actually shows afterwards
  * receipt           - the producer's signed claim binding request to effect

...decide, with no network and no trust in the producer beyond one pinned
issuer key, whether the effect that happened is the effect that was approved.

The verifier never collapses "interrupted" into either success or failure. A
refund that commits while its acknowledgement is lost is reported as
UNCONFIRMED with the exact gap named, which is the honest answer a downstream
reader needs.

Pure standard library + `cryptography` (Ed25519). No I/O except what the caller
passes in.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# Canonicalisation.
# Deterministic bytes for hashing and signing. The exact rule a second
# implementer must reproduce to match our byte pinned vectors:
#   keys sorted by Unicode code point, compact separators (no insignificant
#   whitespace), UTF-8, non ASCII emitted literally (not escaped), and
#   non finite floats rejected rather than emitted as the non standard NaN or
#   Infinity tokens. No Unicode normalisation is applied: inputs must already
#   be in the form the signer used.
# Monetary amounts travel as decimal strings, never floats, so the JCS number
# canonicalisation hazard (0.1 has no exact binary form) never arises; amounts
# are compared with Decimal.

def canonical_bytes(obj: Any) -> bytes:
    """Canonical JSON encoding used for every digest and signature preimage."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(obj: Any) -> str:
    """Hex SHA-256 of the canonical encoding of obj."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def load_json_strict(text: str) -> Any:
    """Parse JSON, rejecting duplicate object keys.

    Duplicate keys let a producer show one value to a signer and another to a
    reader whose parser keeps a different occurrence. A verifier boundary must
    refuse them rather than silently keep the last.
    """
    def _no_dupes(pairs):
        seen: dict = {}
        for k, v in pairs:
            if k in seen:
                raise ValueError(f"duplicate key {k!r}")
            seen[k] = v
        return seen

    def _no_constants(token):
        # json permits the non standard NaN, Infinity and -Infinity tokens by
        # default. A verifier boundary must refuse them rather than admit a
        # non-finite float that the canonical form cannot represent.
        raise ValueError(f"non-finite JSON constant {token!r}")

    return json.loads(text, object_pairs_hook=_no_dupes,
                      parse_constant=_no_constants)


# A canonical monetary amount is a plain decimal string: no leading zeros, no
# exponent, no sign other than a leading minus. Floats and exponent forms are
# refused so the type contract cannot be used to smuggle a numerically equal
# but differently canonicalised value.
_DECIMAL_RE = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?")


def _is_decimal_string(value: Any) -> bool:
    # fullmatch, not match: match plus $ would admit a trailing newline, since
    # Python's $ matches before a final newline.
    return isinstance(value, str) and _DECIMAL_RE.fullmatch(value) is not None


# Verdict model.

class Axis(str, Enum):
    RECEIPT_SIGNATURE = "receipt_signature"
    REQUEST_BINDING = "request_binding"
    EFFECT_BINDING = "effect_binding"
    AMOUNT_CONSISTENCY = "amount_consistency"
    IDEMPOTENCY = "idempotency"
    COMPLETION = "completion"


class Result(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNCONFIRMED = "UNCONFIRMED"


class Overall(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    UNCONFIRMED = "UNCONFIRMED"


@dataclass
class AxisResult:
    axis: Axis
    result: Result
    detail: str


@dataclass
class Verdict:
    overall: Overall
    axes: list[AxisResult] = field(default_factory=list)

    def by_axis(self, axis: Axis) -> AxisResult:
        for a in self.axes:
            if a.axis == axis:
                return a
        raise KeyError(axis)

    def as_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.value,
            "axes": [
                {"axis": a.axis.value, "result": a.result.value, "detail": a.detail}
                for a in self.axes
            ],
        }


# Helpers.

def _money(value: str) -> Decimal:
    """Parse a textual amount; raises on anything non-decimal."""
    return Decimal(str(value))


# The verifier.

def verify(
    approved_request: dict[str, Any],
    observed_effect: dict[str, Any],
    receipt: dict[str, Any],
    issuer_pubkey: Ed25519PublicKey,
) -> Verdict:
    """Independently check that observed_effect is the approved effect.

    Returns a Verdict carrying a per-axis breakdown. The overall rule:
      * any hard axis FAIL           -> REJECT (named axis is the reason)
      * completion UNCONFIRMED only  -> UNCONFIRMED (effect real but unacked)
      * everything PASS              -> ACCEPT
    """
    axes: list[AxisResult] = []

    # Axis 1: receipt signature over the pinned issuer key.
    # Without a valid signature the receipt is worthless; every later binding
    # check would be trusting attacker-chosen digests.
    sig_ok = False
    try:
        sig_hex = receipt.get("sig")
        if not isinstance(sig_hex, str):
            raise ValueError("sig is not a hex string")
        unsigned = {k: v for k, v in receipt.items() if k != "sig"}
        issuer_pubkey.verify(bytes.fromhex(sig_hex), canonical_bytes(unsigned))
        sig_ok = True
        axes.append(AxisResult(Axis.RECEIPT_SIGNATURE, Result.PASS,
                               "signature verifies against pinned issuer key"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        axes.append(AxisResult(Axis.RECEIPT_SIGNATURE, Result.FAIL,
                               f"signature invalid: {type(exc).__name__}"))

    # A non-finite float anywhere in a record makes it non canonicalisable.
    # Compute the expected digests defensively so such a record fails the
    # binding closed rather than raising.
    def _safe_digest(obj):
        try:
            return digest(obj)
        except (ValueError, TypeError):
            return None

    want_req = _safe_digest(approved_request)
    want_eff = _safe_digest(observed_effect)
    rcpt_op = receipt.get("op_id")

    # Axis 2: request binding.
    # The receipt must carry the digest of the approved request AND name the same
    # operation. Checking the digest without the operation identity would let an
    # approval for one operation be paired with the effect of another.
    got_req = receipt.get("request_digest")
    if sig_ok and want_req is not None and got_req == want_req \
            and rcpt_op is not None and rcpt_op == approved_request.get("op_id"):
        axes.append(AxisResult(Axis.REQUEST_BINDING, Result.PASS,
                               "receipt binds this operation's approved request"))
    else:
        if not sig_ok:
            detail = "not checked: receipt untrusted"
        elif want_req is None:
            detail = "approved request is not canonicalisable"
        elif rcpt_op is None or rcpt_op != approved_request.get("op_id"):
            detail = "op_id missing or mismatched between receipt and approved request"
        else:
            detail = f"request_digest {str(got_req)[:12]}.. != {want_req[:12]}.."
        axes.append(AxisResult(Axis.REQUEST_BINDING, Result.FAIL, detail))

    # Axis 3: effect binding.
    # This catches the "a saved success response outlives the real state" case:
    # the receipt pins an effect digest that no longer matches what the reader
    # observes now. It too requires the same operation identity.
    got_eff = receipt.get("effect_digest")
    if sig_ok and want_eff is not None and got_eff == want_eff \
            and rcpt_op is not None and rcpt_op == observed_effect.get("op_id"):
        axes.append(AxisResult(Axis.EFFECT_BINDING, Result.PASS,
                               "receipt binds this operation's observed effect"))
    else:
        if not sig_ok:
            detail = "not checked: receipt untrusted"
        elif want_eff is None:
            detail = "observed effect is not canonicalisable"
        elif rcpt_op is None or rcpt_op != observed_effect.get("op_id"):
            detail = "op_id missing or mismatched between receipt and observed effect"
        else:
            detail = f"effect_digest {str(got_eff)[:12]}.. != {want_eff[:12]}.."
        axes.append(AxisResult(Axis.EFFECT_BINDING, Result.FAIL, detail))

    # Axis 4: amount consistency.
    # The approved amount/currency must equal what the effect reports, and the
    # balance must actually have moved by that amount in the right direction.
    req_amount = approved_request.get("amount")
    eff_amount = observed_effect.get("amount")
    before = observed_effect.get("balance_before")
    after = observed_effect.get("balance_after")
    applied = observed_effect.get("applied_count")
    same_ccy = approved_request.get("currency") == observed_effect.get("currency")
    money_fields = (req_amount, eff_amount, before, after)
    if not same_ccy:
        axes.append(AxisResult(Axis.AMOUNT_CONSISTENCY, Result.FAIL,
                               "currency mismatch"))
    elif not all(_is_decimal_string(x) for x in money_fields):
        # Enforce the type contract: amounts and balances are canonical decimal
        # strings. A float or exponent form is refused rather than coerced.
        axes.append(AxisResult(Axis.AMOUNT_CONSISTENCY, Result.FAIL,
                               "amounts must be canonical decimal strings"))
    elif not isinstance(applied, int) or isinstance(applied, bool) or applied < 0:
        axes.append(AxisResult(Axis.AMOUNT_CONSISTENCY, Result.FAIL,
                               f"applied_count must be a non-negative integer: {applied!r}"))
    else:
        req_amt = _money(req_amount)
        eff_amt = _money(eff_amount)
        delta = _money(after) - _money(before)
        # The ledger must have moved by exactly (amount per application x number
        # of applications). This stays PASS under a legitimate retry that
        # re-applied the SAME amount; whether re-applying was allowed at all is
        # the idempotency axis's job, not this one.
        if req_amt != eff_amt:
            axes.append(AxisResult(Axis.AMOUNT_CONSISTENCY, Result.FAIL,
                                   f"approved {req_amt} != effect {eff_amt}"))
        elif delta != eff_amt * applied:
            axes.append(AxisResult(Axis.AMOUNT_CONSISTENCY, Result.FAIL,
                                   f"balance delta {delta} != {eff_amt} x {applied}"))
        else:
            axes.append(AxisResult(Axis.AMOUNT_CONSISTENCY, Result.PASS,
                                   f"balance moved by {eff_amt} x {applied}"))

    # Axis 5: idempotency.
    # A retry must not apply the refund twice.
    applied = observed_effect.get("applied_count")
    if isinstance(applied, int) and not isinstance(applied, bool) and applied == 1:
        axes.append(AxisResult(Axis.IDEMPOTENCY, Result.PASS,
                               "op applied exactly once"))
    else:
        axes.append(AxisResult(Axis.IDEMPOTENCY, Result.FAIL,
                               f"op applied {applied!r} times"))

    # Axis 6: completion (tri-state).
    # The crux: a refund can commit in the ledger while its acknowledgement is
    # lost. That is neither success nor failure; it is UNCONFIRMED, and the
    # verifier says exactly what is missing. This check certifies realised
    # effects only: any status other than committed or interrupted (failed,
    # pending, missing or unknown) is not something it will certify, so it fails
    # closed rather than pretending to adjudicate it.
    status = observed_effect.get("status")
    if status == "committed":
        axes.append(AxisResult(Axis.COMPLETION, Result.PASS,
                               "status=committed with signed receipt"))
    elif status == "interrupted":
        axes.append(AxisResult(Axis.COMPLETION, Result.UNCONFIRMED,
                               "effect present but completion not acknowledged"))
    else:
        axes.append(AxisResult(Axis.COMPLETION, Result.FAIL,
                               f"unsupported status {status!r}: certifies realised effects only"))

    # Overall rollup.
    hard_axes = (Axis.RECEIPT_SIGNATURE, Axis.REQUEST_BINDING, Axis.EFFECT_BINDING,
                 Axis.AMOUNT_CONSISTENCY, Axis.IDEMPOTENCY)
    results = {a.axis: a.result for a in axes}
    if any(results[h] == Result.FAIL for h in hard_axes) or \
            results[Axis.COMPLETION] == Result.FAIL:
        overall = Overall.REJECT
    elif results[Axis.COMPLETION] == Result.UNCONFIRMED:
        overall = Overall.UNCONFIRMED
    else:
        overall = Overall.ACCEPT

    return Verdict(overall=overall, axes=axes)
