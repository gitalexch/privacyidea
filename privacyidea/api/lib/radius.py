# SPDX-FileCopyrightText: 2026 CHERNOVICH Aleksandr M
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Opt-in FreeRADIUS 3 rlm_rest adapter for PUSH challenge-response."""

import hmac
import re

from flask import current_app, g, jsonify

from privacyidea.lib.challenge import get_challenges
from privacyidea.lib.challenge_types import ChallengeSession
from privacyidea.lib.error import ParameterError
from privacyidea.lib.radiuschallenge import decode_state, encode_state, identity_digest, radius_attributes
from privacyidea.lib.token import get_one_token
from privacyidea.lib.tokens.push_types import PushMode


def is_rest_radius_request(request) -> bool:
    rule = getattr(request, "url_rule", None)
    data = getattr(request, "all_data", {})
    return (rule is not None and rule.rule == "/validate/radiuscheck" and request.method in ("GET", "POST")
            and request.args.get("response_format", data.get("response_format")) == "freeradius")


def _binding(request) -> list:
    data = g.request_data
    return [request.remote_addr, g.client_ip, data.get("radius_nas"),
            data.get("user"), data.get("realm", ""), data.get("resolver", "")]


def prepare_rest_radius_request(request):
    """Decode State before pre-policies and join only an authenticated transaction id."""
    data = request.all_data
    raw = g.request_data
    if not isinstance(raw.get("user"), str) or not raw["user"]:
        raise ParameterError("The FreeRADIUS response format requires a user")
    nas = raw.get("radius_nas")
    if not isinstance(nas, str) or not nas or len(nas) > 256:
        raise ParameterError("The FreeRADIUS response format requires radius_nas")
    if any(key in raw for key in ("transaction_id", "serial", "credential_id", "credentialid", "cancel_enrollment")):
        raise ParameterError("Use user and the signed State with the FreeRADIUS response format")
    state = raw.get("state", "")
    if state != "":
        try:
            transaction_id, identity = decode_state(state, _binding(request), current_app.secret_key)
        except (ValueError, TypeError):
            raise ParameterError("Invalid RADIUS State")
        g.radius_rest_identity = identity
        data["state"] = data["transaction_id"] = transaction_id
        return transaction_id
    return None


def _push_challenges(transaction_id, user):
    if not isinstance(transaction_id, str) or not re.fullmatch(r"[0-9]{1,64}", transaction_id):
        raise ParameterError("Invalid RADIUS transaction id")
    challenges = get_challenges(transaction_id=transaction_id)
    if not challenges or any(not challenge.is_valid() for challenge in challenges):
        raise ParameterError("Unknown or expired RADIUS State")
    for challenge in challenges:
        token = get_one_token(serial=challenge.serial, silent_fail=True)
        data = challenge.get_data()
        if (token is None or token.get_tokentype() != "push" or token.user != user
                or challenge.get_session() == ChallengeSession.ENROLLMENT
                or data.get("mode") not in (PushMode.STANDARD, PushMode.REQUIRE_PRESENCE)):
            raise ParameterError("This challenge is not supported by the FreeRADIUS response format")
    return challenges


def validate_rest_radius_continuation(request):
    """Recheck ownership after identity-rewriting pre-policies, before authentication."""
    if request.all_data.get("push_wait"):
        raise ParameterError("The FreeRADIUS response format requires push_wait to be disabled")
    if getattr(g, "radius_rest_identity", None) is not None:
        if not hmac.compare_digest(g.radius_rest_identity, identity_digest(request.User)):
            raise ParameterError("Invalid RADIUS State")
        _push_challenges(request.all_data["transaction_id"], request.User)
        return {"verified": False}
    return None


def construct_rest_radius_response(request, response):
    """Shape the final policy-checked response; all errors fail closed."""
    packet_type, state, message = "Access-Reject", None, None
    content = response.get_json(silent=True) if response.is_json else None
    if 200 <= response.status_code < 300 and isinstance(content, dict):
        result = content.get("result") or {}
        detail = content.get("detail") or {}
        if isinstance(result, dict) and isinstance(detail, dict) and result.get("status") is True:
            if result.get("value") is True and getattr(g, "radius_rest_view_success", False):
                packet_type = "Access-Accept"
            elif result.get("value") is False and detail.get("multi_challenge"):
                transaction_id = detail.get("transaction_id")
                try:
                    challenges = _push_challenges(transaction_id, request.User)
                    state = encode_state(transaction_id, identity_digest(request.User),
                                         _binding(request), current_app.secret_key)
                    presence = [f"Select {challenge.get_data()['correct_answer']} on {challenge.serial}."
                                for challenge in challenges if challenge.get_data().get("correct_answer")]
                    prefix = " ".join(presence)
                    if len(prefix.encode("utf-8")) > 253:
                        raise ValueError("Presence options do not fit in Reply-Message")
                except (ParameterError, ValueError, TypeError):
                    state = None
                else:
                    packet_type = "Access-Challenge"
                    message = detail.get("message")
                    if not isinstance(message, str) or not message:
                        message = "Confirm the PUSH on your device, then continue."
                    if prefix:
                        message = f"{prefix} {message}"
    shaped = jsonify(radius_attributes(packet_type, state, message))
    shaped.status_code = 401 if packet_type == "Access-Reject" else 200
    return shaped
