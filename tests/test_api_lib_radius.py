# SPDX-FileCopyrightText: 2026 CHERNOVICH Aleksandr M
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail-closed response shaping independent of the authentication view."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacyidea.api.lib import radius
from privacyidea.lib.radiuschallenge import decode_state, encode_state, identity_digest
from privacyidea.lib.error import ParameterError


class Response:
    def __init__(self, content, status=200, is_json=True):
        self.content = content
        self.status_code = status
        self.is_json = is_json

    def get_json(self, silent=False):
        return self.content


class RadiusAdapterTestCase(unittest.TestCase):
    def setUp(self):
        self.user = SimpleNamespace(uid="100", resolver="users", realm="realm1", login="alice")
        self.request = SimpleNamespace(User=self.user, remote_addr="radius.example", args={}, method="POST",
                                       all_data={}, url_rule=SimpleNamespace(rule="/validate/radiuscheck"))
        self.raw = {"user": "alice", "radius_nas": "nas.example"}
        self.globals = SimpleNamespace(request_data=self.raw, client_ip="radius.example")
        self.app = SimpleNamespace(secret_key="test-only-radius-state-secret")
        self.patches = [patch.object(radius, "g", self.globals),
                        patch.object(radius, "current_app", self.app),
                        patch.object(radius, "jsonify", side_effect=Response)]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def shape(self, content, status=200, is_json=True):
        return radius.construct_rest_radius_response(self.request, Response(content, status, is_json))

    def assert_rejected(self, response):
        self.assertEqual(401, response.status_code)
        self.assertEqual("Access-Reject", response.content["control:Response-Packet-Type"]["value"])
        self.assertNotIn("reply:State", response.content)

    def test_errors_html_and_unverified_success_fail_closed(self):
        for content, status, is_json in (({}, 200, True), (None, 400, False), ("html", 500, False),
                                        ({"result": {"status": False, "value": True}}, 200, True),
                                        ({"result": [True]}, 200, True),
                                        ({"result": {"status": True, "value": False}, "detail": [True]}, 200, True),
                                        ({"result": {"status": True, "value": False}}, 200, True),
                                        ({"result": {"status": True, "value": True}}, 200, True)):
            with self.subTest(content=content):
                self.assert_rejected(self.shape(content, status, is_json))

    def test_final_success_requires_both_view_and_final_policy_success(self):
        self.globals.radius_rest_view_success = True
        success = {"result": {"status": True, "value": True}}
        response = self.shape(success)
        self.assertEqual(200, response.status_code)
        self.assertEqual("Access-Accept", response.content["control:Response-Packet-Type"]["value"])
        self.assert_rejected(self.shape(success, status=403))
        self.assert_rejected(self.shape({"result": {"status": False, "value": True}}))

    def test_challenge_has_signed_octets_and_presence_prompt(self):
        challenge = SimpleNamespace(serial="push1", get_data=lambda: {"correct_answer": "42"})
        content = {"result": {"status": True, "value": False},
                   "detail": {"transaction_id": "123", "multi_challenge": [{}], "message": "Confirm"}}
        with patch.object(radius, "_push_challenges", return_value=[challenge]):
            response = self.shape(content)
        self.assertEqual("Access-Challenge", response.content["control:Response-Packet-Type"]["value"])
        state = bytes.fromhex(response.content["reply:State"]["value"][2:]).decode()
        self.assertEqual(("123", identity_digest(self.user)),
                         decode_state(state, radius._binding(self.request), self.app.secret_key))
        self.assertIn("Select 42", response.content["reply:Reply-Message"]["value"])

    def test_unknown_or_unsupported_transaction_is_never_a_challenge(self):
        content = {"result": {"status": True, "value": False},
                   "detail": {"transaction_id": "123", "multi_challenge": [{}]}}
        with patch.object(radius, "_push_challenges", side_effect=ParameterError("Unknown transaction")):
            self.assert_rejected(self.shape(content))
        with patch.object(radius, "get_challenges") as query:
            for transaction_id in (None, "", [], "bad"):
                with self.subTest(transaction_id=transaction_id), self.assertRaises(ParameterError):
                    radius._push_challenges(transaction_id, self.user)
            query.assert_not_called()

    def test_request_preparation_and_identity_binding(self):
        state = encode_state("123", identity_digest(self.user), radius._binding(self.request), self.app.secret_key)
        self.raw["state"] = state
        self.assertEqual("123", radius.prepare_rest_radius_request(self.request))
        self.assertEqual("123", self.request.all_data["transaction_id"])
        with patch.object(radius, "_push_challenges") as check:
            self.assertEqual({"verified": False}, radius.validate_rest_radius_continuation(self.request))
            check.assert_called_once_with("123", self.user)
            self.user.uid = "other"
            with self.assertRaises(ParameterError):
                radius.validate_rest_radius_continuation(self.request)

    def test_missing_nas_and_unsigned_transaction_are_rejected(self):
        for raw in ({"user": "alice"}, {**self.raw, "transaction_id": "123"}, {**self.raw, "state": "123"}):
            self.globals.request_data = raw
            with self.subTest(raw=raw), self.assertRaises(ParameterError):
                radius.prepare_rest_radius_request(self.request)

    def test_legacy_route_and_other_endpoint_are_not_selected(self):
        self.assertFalse(radius.is_rest_radius_request(self.request))
        self.request.args["response_format"] = "freeradius"
        self.assertTrue(radius.is_rest_radius_request(self.request))
        self.request.url_rule.rule = "/validate/check"
        self.assertFalse(radius.is_rest_radius_request(self.request))
        self.request.url_rule.rule = "/validate/radiuscheck"
        self.request.method = "OPTIONS"
        self.assertFalse(radius.is_rest_radius_request(self.request))

    def test_only_live_supported_pushes_of_the_current_user_can_continue(self):
        challenge = SimpleNamespace(serial="push1", is_valid=lambda: True,
                                     get_data=lambda: {"mode": "standard"}, get_session=lambda: "")
        token = SimpleNamespace(user=self.user, get_tokentype=lambda: "push")
        with patch.object(radius, "get_challenges", return_value=[challenge]), \
                patch.object(radius, "get_one_token", return_value=token):
            self.assertEqual([challenge], radius._push_challenges("123", self.user))
            for other_user in (None, SimpleNamespace(uid="other")):
                token.user = other_user
                with self.subTest(user=other_user), self.assertRaises(ParameterError):
                    radius._push_challenges("123", self.user)
            token.user = self.user
            for mode in ("code_to_phone", "unsupported", None):
                challenge.get_data = lambda: {"mode": mode}
                with self.subTest(mode=mode), self.assertRaises(ParameterError):
                    radius._push_challenges("123", self.user)
            challenge.get_data = lambda: {"mode": "standard"}
            challenge.is_valid = lambda: False
            with self.assertRaises(ParameterError):
                radius._push_challenges("123", self.user)
