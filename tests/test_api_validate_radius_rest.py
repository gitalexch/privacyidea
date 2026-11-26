# SPDX-FileCopyrightText: 2026 CHERNOVICH Aleksandr M
# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end API coverage of the opt-in RADIUS PUSH continuation."""

from base64 import b32encode
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from privacyidea.lib.challenge import delete_challenges, get_challenges
from privacyidea.lib.challenge_types import ChallengeSession
from privacyidea.lib.conditional_access.authentication_event_types import AuthEventType
from privacyidea.lib.policy import SCOPE, set_policy
from privacyidea.lib.token import enable_token, get_one_token
from privacyidea.lib.tokens.push_types import PushAction
from privacyidea.lib.tokens.pushtoken import POLL_ONLY, strip_pem_headers
from .authlog_utils import assert_authentication_log
from .base import MyApiTestCase, force_expire_challenges


class RadiusRestPushTestCase(MyApiTestCase):
    user = "selfservice"
    serial = "PIRADIUSREST"
    pin = "radius-pin"
    nas = "nas.example"
    path = "/validate/radiuscheck?response_format=freeradius"

    def setUp(self):
        self.set_up_database()
        self.setUp_user_realms()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        set_policy("radius-poll-only", scope=SCOPE.ENROLL,
                   action=f"{PushAction.FIREBASE_CONFIG}={POLL_ONLY},"
                          f"{PushAction.REGISTRATION_URL}=https://privacyidea.example/ttype/push,"
                          f"{PushAction.TTL}=10")
        response = self.post("/token/init", {"type": "push", "pin": self.pin, "user": self.user,
                                           "realm": self.realm1, "serial": self.serial, "genkey": 1},
                             headers={"Authorization": self.at})
        self.assertEqual(200, response.status_code, response.json)
        response = self.post("/ttype/push", {
            "enrollment_credential": response.json["detail"]["enrollment_credential"], "serial": self.serial,
            "pubkey": strip_pem_headers(public_key).replace("+", "-").replace("/", "_"), "fbtoken": "test-device"})
        self.assertEqual(200, response.status_code, response.json)

    def post(self, path, data, headers=None, **kwargs):
        with self.app.test_request_context(path, method="POST", data=data,
                                           headers={"User-Agent": "FreeRADIUS", **(headers or {})}, **kwargs):
            return self.app.full_dispatch_request()

    def radius(self, state="", **overrides):
        data = {"user": self.user, "realm": self.realm1, "pass": self.pin,
                "radius_nas": self.nas, "state": state, **overrides}
        return self.post(self.path, data)

    def packet(self, response, expected):
        self.assertEqual(401 if expected == "Access-Reject" else 200, response.status_code, response.json)
        self.assertEqual(expected, response.json["control:Response-Packet-Type"]["value"], response.json)
        self.assertIn("no-store", response.headers["Cache-Control"])
        if expected != "Access-Challenge":
            self.assertNotIn("reply:State", response.json)

    def start(self):
        response = self.radius()
        self.packet(response, "Access-Challenge")
        encoded = response.json["reply:State"]["value"]
        state = bytes.fromhex(encoded[2:]).decode("ascii")
        challenge, = get_challenges(serial=self.serial)
        return state, challenge.transaction_id

    def answer(self, transaction_id, decline=False, reason=None, presence=None):
        challenge, = get_challenges(serial=self.serial, transaction_id=transaction_id)
        text = f"{challenge.challenge}|{self.serial}"
        if decline:
            text += "|decline"
            if reason:
                text += f"|{reason}"
        if presence:
            text += f"|{presence}"
        signature = self.key.sign(text.encode(), padding.PKCS1v15(), hashes.SHA256())
        data = {"serial": self.serial, "signature": b32encode(signature).decode()}
        if presence:
            data["presence_answer"] = presence
        if decline:
            data["decline"] = "true"
            if reason:
                data["decline_reason"] = reason
        response = self.post("/ttype/push", data)
        self.assertEqual(200, response.status_code, response.json)
        self.assertIs(True, response.json["result"]["value"])

    def test_pending_approval_and_replay(self):
        state, transaction_id = self.start()
        count = get_one_token(serial=self.serial).token.failcount
        response = self.radius(state, **{"pass": "continue"})
        self.packet(response, "Access-Challenge")
        self.assertEqual(state, bytes.fromhex(response.json["reply:State"]["value"][2:]).decode())
        self.assertEqual(1, len(get_challenges(serial=self.serial)))
        self.assertEqual(count, get_one_token(serial=self.serial).token.failcount)
        assert_authentication_log([AuthEventType.CHALLENGE_TRIGGERED], transaction_id=transaction_id)
        self.answer(transaction_id)
        self.packet(self.radius(state, **{"pass": "continue"}), "Access-Accept")
        self.assertEqual([], get_challenges(transaction_id=transaction_id))
        self.packet(self.radius(state), "Access-Reject")

    def test_wrong_user_nas_and_signature_do_not_consume_approval(self):
        state, transaction_id = self.start()
        self.answer(transaction_id)
        for overrides in ({"user": "root"}, {"radius_nas": "other-nas"}, {"realm": self.realm1.upper()}):
            with self.subTest(overrides=overrides):
                self.packet(self.radius(state, **overrides), "Access-Reject")
        tampered = state[:-1] + ("0" if state[-1] != "0" else "1")
        self.packet(self.radius(tampered), "Access-Reject")
        self.assertEqual(1, len(get_challenges(transaction_id=transaction_id)))
        self.packet(self.radius(state), "Access-Accept")

    def test_expired_state_is_rejected_without_creating_another_push(self):
        state, transaction_id = self.start()
        force_expire_challenges(transaction_id)
        self.packet(self.radius(state), "Access-Reject")
        self.assertFalse(any(challenge.is_valid() for challenge in get_challenges(serial=self.serial)))

    def test_declined_or_cancelled_push_is_rejected(self):
        for reason, session in ((None, ChallengeSession.DECLINED), ("cancelled", ChallengeSession.CANCELLED)):
            with self.subTest(reason=reason):
                state, transaction_id = self.start()
                self.answer(transaction_id, decline=True, reason=reason)
                challenge, = get_challenges(transaction_id=transaction_id)
                self.assertEqual(session, challenge.get_session())
                self.packet(self.radius(state), "Access-Reject")
                delete_challenges(transaction_id=transaction_id)

    def test_disabled_token_and_authorization_failure_are_rejected(self):
        state, transaction_id = self.start()
        self.answer(transaction_id)
        enable_token(self.serial, enable=False)
        self.packet(self.radius(state), "Access-Reject")
        enable_token(self.serial, enable=True)
        set_policy("radius-deny-push", scope=SCOPE.AUTHZ, action="serial=DENIED")
        self.packet(self.radius(state), "Access-Reject")

    def test_invalid_requests_and_legacy_format(self):
        for data in ({"user": self.user, "pass": self.pin},
                     {"user": self.user, "pass": self.pin, "radius_nas": self.nas, "state": "123"},
                     {"user": self.user, "pass": self.pin, "radius_nas": self.nas, "transaction_id": "123"}):
            with self.subTest(data=data):
                self.packet(self.post(self.path, data), "Access-Reject")
        response = self.post("/validate/radiuscheck", {"user": self.user, "realm": self.realm1, "pass": "wrong"})
        self.assertEqual(400, response.status_code)
        self.assertEqual(b"", response.data)

    def test_wait_policy_is_refused_before_push_is_triggered(self):
        set_policy("radius-wait", scope=SCOPE.AUTH, action=f"{PushAction.WAIT}=10")
        self.packet(self.radius(), "Access-Reject")
        self.assertEqual([], get_challenges(serial=self.serial))

    def test_client_supplied_completion_marker_is_ignored(self):
        state, _ = self.start()
        self.packet(self.radius(state, radius_rest="verified"), "Access-Challenge")

    def test_a_policy_shortcut_cannot_redeem_state_without_consuming_push(self):
        state, transaction_id = self.start()
        self.answer(transaction_id)
        with patch("privacyidea.api.validate.check_user_pass", return_value=(True, {})):
            self.packet(self.radius(state), "Access-Reject")
        self.assertEqual(1, len(get_challenges(transaction_id=transaction_id)))
        self.packet(self.radius(state), "Access-Accept")

    def test_presence_choice_is_sent_to_the_nas_and_required_on_the_phone(self):
        set_policy("radius-presence", scope=SCOPE.AUTH, action=f"{PushAction.REQUIRE_PRESENCE}=true")
        state, transaction_id = self.start()
        challenge, = get_challenges(transaction_id=transaction_id)
        choice = challenge.get_data()["correct_answer"]
        response = self.radius(state)
        self.packet(response, "Access-Challenge")
        self.assertIn(f"Select {choice}", response.json["reply:Reply-Message"]["value"])
        self.answer(transaction_id, presence=choice)
        self.packet(self.radius(state), "Access-Accept")
