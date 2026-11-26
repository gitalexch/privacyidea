# SPDX-FileCopyrightText: 2026 CHERNOVICH Aleksandr M
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wire format for the opt-in FreeRADIUS REST challenge adapter."""

import hashlib
import hmac
import json
import re


def identity_digest(user) -> str:
    """Bind a State to a resolved account, including its realm and resolver."""
    identity = [user.uid, user.resolver, user.realm, user.login]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()[:32]


def _mac(payload: str, binding: list, secret: str | bytes) -> str:
    if not secret:
        raise ValueError("A shared SECRET_KEY is required for RADIUS State")
    key = secret.encode() if isinstance(secret, str) else secret
    message = json.dumps(["privacyidea-radius-rest-v1", payload, binding], ensure_ascii=True).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def encode_state(transaction_id: str, identity: str, binding: list, secret: str | bytes) -> str:
    """Return an ASCII State smaller than the RADIUS limit of 253 octets."""
    if not re.fullmatch(r"[0-9]{1,64}", transaction_id):
        raise ValueError("Unsupported transaction id")
    if not re.fullmatch(r"[0-9a-f]{32}", identity):
        raise ValueError("Invalid account binding")
    payload = f"pi1.{transaction_id}.{identity}"
    return f"{payload}.{_mac(payload, binding, secret)}"


def decode_state(state: str, binding: list, secret: str | bytes) -> tuple[str, str]:
    """Verify the request/NAS binding before exposing the transaction id."""
    if not isinstance(state, str) or not re.fullmatch(r"pi1\.[0-9]{1,64}\.[0-9a-f]{32}\.[0-9a-f]{64}", state):
        raise ValueError("Invalid RADIUS State")
    payload, signature = state.rsplit(".", 1)
    if not hmac.compare_digest(signature, _mac(payload, binding, secret)):
        raise ValueError("Invalid RADIUS State")
    _, transaction_id, identity = payload.split(".")
    return transaction_id, identity


def radius_attributes(packet_type: str, state: str = None, message: str = None) -> dict:
    """Build rlm_rest JSON without enabling expansion of response values."""
    def attribute(value):
        return {"op": ":=", "value": value, "do_xlat": False}

    attributes = {"control:Response-Packet-Type": attribute(packet_type)}
    if state is not None:
        attributes["reply:State"] = attribute("0x" + state.encode("ascii").hex())
    if message:
        # Reply-Message is a RADIUS string with a maximum payload of 253 octets.
        attributes["reply:Reply-Message"] = attribute(message.encode("utf-8")[:253].decode("utf-8", "ignore"))
    return attributes


def pending_push_response(tokens, transaction_id: str) -> dict | None:
    """Keep an unanswered PUSH pending without checking a wrong response."""
    from privacyidea.lib.challenge import get_challenges

    if not tokens or any(token.get_tokentype() != "push" for token in tokens):
        return None
    serials = {token.get_serial() for token in tokens}
    challenges = [challenge for challenge in get_challenges(transaction_id=transaction_id)
                  if challenge.serial in serials and challenge.is_valid()]
    if any(challenge.get_otp_status()[1] is True for challenge in challenges):
        return None
    if not any(challenge.is_open() for challenge in challenges):
        return None
    message = "Confirm the PUSH on your device, then continue."
    return {"transaction_id": transaction_id, "message": message, "messages": [message],
            "multi_challenge": [{"serial": challenge.serial, "type": "push",
                                 "transaction_id": transaction_id, "message": message}
                                for challenge in challenges if challenge.is_open()]}
