# SPDX-FileCopyrightText: 2026 CHERNOVICH Aleksandr M
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RADIUS State authentication and rlm_rest wire format."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privacyidea.lib.radiuschallenge import (decode_state, encode_state, identity_digest,
                                            pending_push_response, radius_attributes)


class RadiusStateTestCase(unittest.TestCase):
    secret = b"test-only-shared-radius-state-key"
    binding = ["radius.example", "radius.example", "nas.example", "alice", "realm1", ""]
    identity = "a" * 32
    transaction = "1234" * 5

    def state(self, transaction=None):
        return encode_state(transaction or self.transaction, self.identity, self.binding, self.secret)

    def test_roundtrip_and_maximum_size(self):
        state = self.state()
        self.assertEqual((self.transaction, self.identity), decode_state(state, self.binding, self.secret))
        self.assertLessEqual(len(self.state("9" * 64).encode("ascii")), 253)

    def test_tampering_and_foreign_scope_fail(self):
        state = self.state()
        for index, value in enumerate(self.binding):
            changed = list(self.binding)
            changed[index] = value + "other"
            with self.subTest(index=index), self.assertRaises(ValueError):
                decode_state(state, changed, self.secret)
        for changed in (state.replace(self.transaction, "0" * 20),
                        state.replace(self.identity, "b" * 32), state[:-1] + "x"):
            with self.subTest(state=changed), self.assertRaises(ValueError):
                decode_state(changed, self.binding, self.secret)
        with self.assertRaises(ValueError):
            decode_state(state, self.binding, b"another-secret")

    def test_malformed_states_fail(self):
        for state in (None, False, 123, {}, "", self.transaction, "pi1." + "9" * 300, self.state() + "\n"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                decode_state(state, self.binding, self.secret)
        for transaction in ("", "123\n", "a", "1" * 65):
            with self.subTest(transaction=transaction), self.assertRaises(ValueError):
                encode_state(transaction, self.identity, self.binding, self.secret)
        with self.assertRaises(ValueError):
            encode_state(self.transaction, self.identity, self.binding, b"")

    def test_resolved_account_binding(self):
        user = SimpleNamespace(uid="100", resolver="users", realm="realm1", login="alice")
        initial = identity_digest(user)
        for key in vars(user):
            changed = SimpleNamespace(**vars(user))
            setattr(changed, key, "different")
            with self.subTest(key=key):
                self.assertNotEqual(initial, identity_digest(changed))

    def test_state_octets_and_untrusted_text(self):
        state = self.state()
        message = "%{exec:untrusted} " + "\u0416" * 200
        attributes = radius_attributes("Access-Challenge", state, message)
        encoded = attributes["reply:State"]["value"]
        self.assertEqual(state, bytes.fromhex(encoded[2:]).decode("ascii"))
        self.assertLessEqual(len(attributes["reply:Reply-Message"]["value"].encode()), 253)
        self.assertTrue(attributes["reply:Reply-Message"]["value"].startswith("%{exec:untrusted}"))
        for attribute in attributes.values():
            self.assertEqual(":=", attribute["op"])
            self.assertIs(False, attribute["do_xlat"])

    def test_terminal_replies_have_no_state(self):
        for packet_type in ("Access-Accept", "Access-Reject"):
            self.assertEqual({"control:Response-Packet-Type": {
                "op": ":=", "value": packet_type, "do_xlat": False}}, radius_attributes(packet_type))


class PendingPushTestCase(unittest.TestCase):
    @staticmethod
    def token(serial="push1", kind="push"):
        return SimpleNamespace(get_serial=lambda: serial, get_tokentype=lambda: kind)

    @staticmethod
    def challenge(serial="push1", valid=True, approved=False, open=True):
        return SimpleNamespace(serial=serial, is_valid=lambda: valid, is_open=lambda: open,
                               get_otp_status=lambda: (0, approved))

    def test_pending_and_multiple_pushes(self):
        challenges = [self.challenge(), self.challenge("push2")]
        with patch("privacyidea.lib.challenge.get_challenges", return_value=challenges):
            response = pending_push_response([self.token(), self.token("push2")], "123")
        self.assertEqual("123", response["transaction_id"])
        self.assertEqual({"push1", "push2"}, {entry["serial"] for entry in response["multi_challenge"]})

    def test_terminal_foreign_and_unsupported_challenges_are_not_pending(self):
        for challenge in (self.challenge(valid=False), self.challenge(approved=True, open=False),
                          self.challenge(open=False), self.challenge(serial="foreign")):
            with self.subTest(challenge=challenge):
                with patch("privacyidea.lib.challenge.get_challenges", return_value=[challenge]):
                    self.assertIsNone(pending_push_response([self.token()], "123"))
        self.assertIsNone(pending_push_response([self.token(kind="hotp")], "123"))
        self.assertIsNone(pending_push_response([], "123"))

    def test_approval_on_one_device_enters_normal_authentication(self):
        with patch("privacyidea.lib.challenge.get_challenges", return_value=[
                self.challenge(), self.challenge("push2", approved=True, open=False)]):
            self.assertIsNone(pending_push_response([self.token(), self.token("push2")], "123"))
