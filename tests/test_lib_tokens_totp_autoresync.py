"""Exercise bounded TOTP autoresync through OTP validation and the API."""
from unittest import mock

from privacyidea.lib.autoresync import AUTORESYNC_KEY, AutoResyncResult
from privacyidea.lib.config import delete_privacyidea_config, set_prepend_pin, set_privacyidea_config
from privacyidea.lib.token import init_token
from privacyidea.lib.tokens.HMAC import HmacOtp
from .base import MyTestCase


class TOTPAutoresyncWindowTestCase(MyTestCase):
    first_counter = 47251640
    server_counter = 47251600
    otpkey = "3132333435363738393031323334353637383930"

    def setUp(self):
        super().setUp()
        set_privacyidea_config("AutoResync", True)
        set_privacyidea_config("AutoResyncTimeout", 300)
        self.create_token()

    def create_token(self, window=300, step=30):
        self.token = init_token({"type": "totp", "otpkey": self.otpkey, "otplen": 6,
                                 "timeStep": step, "timeWindow": window, "timeShift": 0})
        self.token.set_sync_window(100)
        self.token.set_otp_count(self.first_counter - 10)
        self.otp = HmacOtp(self.token.token.get_otpkey(), digits=6)
        self.server_time = self.server_counter * step

    def check_counter(self, counter, elapsed=0):
        otp = self.otp.generate(counter=counter, inc_counter=False)
        self.token.auth_details.clear()
        with mock.patch("privacyidea.lib.tokens.totptoken.time.time",
                        return_value=self.server_time + elapsed):
            return self.token.check_otp(otp)

    def start_pair(self):
        self.assertEqual(self.check_counter(self.first_counter), -1)
        self.assertEqual(int(self.token.get_tokeninfo("otp1c")), self.first_counter)
        self.assertEqual(int(self.token.get_tokeninfo("dueDate")),
                         self.server_time + self.token.get_autoresync_timeout())
        self.assertEqual(self.token.auth_details[AUTORESYNC_KEY], AutoResyncResult.STARTED)

    def assert_pair_cleared(self):
        self.assertNotIn("otp1c", self.token.get_tokeninfo())
        self.assertNotIn("dueDate", self.token.get_tokeninfo())

    def test_accepts_successor_skips_and_window_boundary(self):
        for gap in (1, 2, 10):
            with self.subTest(gap=gap):
                self.create_token()
                self.start_pair()
                second = self.first_counter + gap
                elapsed = gap * 30 - 1
                self.assertEqual(self.check_counter(second, elapsed), second)
                self.assertEqual(self.token.get_otp_count(), second)
                self.assertEqual(self.token.timeshift, second * 30 - self.server_time - elapsed)
                self.assertEqual(self.token.auth_details[AUTORESYNC_KEY], AutoResyncResult.SUCCESSFUL)
                self.assert_pair_cleared()

    def test_long_timeout_does_not_widen_window_cap(self):
        set_privacyidea_config("AutoResyncTimeout", 3600)
        for gap, accepted in ((10, True), (11, False)):
            with self.subTest(gap=gap):
                self.create_token()
                self.start_pair()
                second = self.first_counter + gap
                self.assertEqual(self.check_counter(second, elapsed=60), second if accepted else -1)
                self.assert_pair_cleared()

    def test_timeout_can_restrict_a_larger_window(self):
        set_privacyidea_config("AutoResyncTimeout", 119)
        for gap, accepted in ((3, True), (4, False)):
            with self.subTest(gap=gap):
                self.create_token(window=900)
                self.start_pair()
                second = self.first_counter + gap
                self.assertEqual(self.check_counter(second, elapsed=60), second if accepted else -1)
                self.assert_pair_cleared()

    def test_non_multiple_window_rounds_down(self):
        for gap, accepted in ((2, True), (3, False)):
            with self.subTest(gap=gap):
                self.create_token(window=89)
                self.start_pair()
                second = self.first_counter + gap
                self.assertEqual(self.check_counter(second, elapsed=60), second if accepted else -1)
                self.assert_pair_cleared()

    def test_small_window_preserves_exact_successor(self):
        for window in (1, 30, 59):
            for gap, accepted in ((1, True), (2, False)):
                with self.subTest(window=window, gap=gap):
                    self.create_token(window=window)
                    self.start_pair()
                    second = self.first_counter + gap
                    self.assertEqual(self.check_counter(second, elapsed=30), second if accepted else -1)
                    self.assert_pair_cleared()

    def test_token_window_overrides_global_setting(self):
        set_privacyidea_config("totp.timeWindow", 30)
        self.start_pair()
        second = self.first_counter + 10
        self.assertEqual(self.check_counter(second, elapsed=299), second)

    def test_global_window_when_token_has_no_override(self):
        set_privacyidea_config("totp.timeWindow", 90)
        for gap, accepted in ((3, True), (4, False)):
            with self.subTest(gap=gap):
                self.create_token()
                self.token.remove_tokeninfo("timeWindow")
                self.start_pair()
                second = self.first_counter + gap
                self.assertEqual(self.check_counter(second, elapsed=60), second if accepted else -1)

    def test_default_window_when_no_setting_exists(self):
        delete_privacyidea_config("totp.timeWindow")
        for gap, accepted in ((6, True), (7, False)):
            with self.subTest(gap=gap):
                self.create_token()
                self.token.remove_tokeninfo("timeWindow")
                self.start_pair()
                second = self.first_counter + gap
                self.assertEqual(self.check_counter(second, elapsed=60), second if accepted else -1)

    def test_sixty_second_step(self):
        for gap, accepted in ((5, True), (6, False)):
            with self.subTest(gap=gap):
                self.create_token(step=60)
                self.start_pair()
                second = self.first_counter + gap
                self.assertEqual(self.check_counter(second, elapsed=299), second if accepted else -1)

    def test_expired_or_legacy_pair_starts_again(self):
        for elapsed, legacy in ((299, False), (300, False), (301, False), (30, True)):
            with self.subTest(elapsed=elapsed, legacy=legacy):
                self.create_token()
                self.start_pair()
                if legacy:
                    self.token.remove_tokeninfo("dueDate")
                second = self.first_counter + 2
                result = self.check_counter(second, elapsed)
                if elapsed < 300 and not legacy:
                    self.assertEqual(result, second)
                    self.assert_pair_cleared()
                else:
                    self.assertEqual(result, -1)
                    self.assertEqual(int(self.token.get_tokeninfo("otp1c")), second)
                    self.assertEqual(self.check_counter(second + 1, elapsed + 30), second + 1)
                    self.assert_pair_cleared()

    def test_rejects_duplicate_and_older_second_counter(self):
        for gap in (0, -1):
            with self.subTest(gap=gap):
                self.create_token()
                self.start_pair()
                self.assertEqual(self.check_counter(self.first_counter + gap, elapsed=30), -1)
                self.assert_pair_cleared()

    def test_rejects_pair_overtaken_by_another_authentication(self):
        self.start_pair()
        self.token.set_otp_count(self.first_counter + 1)
        self.assertEqual(self.check_counter(self.first_counter + 2, elapsed=60), -1)
        self.assert_pair_cleared()

    def test_rejects_used_first_counter_with_fresh_second(self):
        self.token.set_otp_count(self.first_counter)
        self.start_pair()
        self.assertEqual(self.check_counter(self.first_counter + 1, elapsed=30), -1)
        self.assert_pair_cleared()

    def test_reduced_window_restricts_pending_pair(self):
        self.start_pair()
        self.token.write_tokeninfo("timeWindow", 30)
        self.assertEqual(self.check_counter(self.first_counter + 2, elapsed=60), -1)
        self.assert_pair_cleared()

    def test_reduced_timeout_restricts_pending_pair(self):
        self.start_pair()
        set_privacyidea_config("AutoResyncTimeout", 119)
        self.assertEqual(self.check_counter(self.first_counter + 4, elapsed=60), -1)
        self.assert_pair_cleared()

    def test_sync_window_still_limits_both_candidates(self):
        self.token.set_sync_window(10)
        self.assertEqual(self.check_counter(self.first_counter), -1)
        self.assert_pair_cleared()
        self.token.set_sync_window(100)
        self.start_pair()
        self.token.set_sync_window(10)
        self.assertEqual(self.check_counter(self.first_counter + 2, elapsed=60), -1)
        self.assertEqual(int(self.token.get_tokeninfo("otp1c")), self.first_counter)

    def test_invalid_timeout_uses_existing_fallback(self):
        set_privacyidea_config("AutoResyncTimeout", "not a number")
        self.start_pair()
        second = self.first_counter + 10
        self.assertEqual(self.check_counter(second, elapsed=299), second)

    def test_short_timeout_keeps_upstream_minimum(self):
        set_privacyidea_config("AutoResyncTimeout", 0)
        self.start_pair()
        self.assertEqual(int(self.token.get_tokeninfo("dueDate")), self.server_time + 90)
        second = self.first_counter + 3
        self.assertEqual(self.check_counter(second, elapsed=89), second)

    def test_disabled_autoresync_and_normal_validation(self):
        set_privacyidea_config("AutoResync", False)
        self.assertEqual(self.check_counter(self.first_counter), -1)
        self.assert_pair_cleared()
        set_privacyidea_config("AutoResync", True)
        self.token.set_otp_count(self.server_counter - 1)
        self.assertEqual(self.check_counter(self.server_counter), self.server_counter)
        self.assert_pair_cleared()

    def test_validation_api_accepts_gap_and_rejects_replay(self):
        set_prepend_pin(True)
        self.token.set_pin("testpin")
        self.token.save()
        for counter, elapsed, expected, failcount in (
                (self.first_counter, 0, False, 1),
                (self.first_counter + 2, 60, True, 0),
                (self.first_counter + 2, 61, False, 1)):
            with self.subTest(counter=counter, elapsed=elapsed):
                self.reset_flask_g()
                otp = self.otp.generate(counter=counter, inc_counter=False)
                with mock.patch("privacyidea.lib.tokens.totptoken.time.time",
                                return_value=self.server_time + elapsed):
                    with self.app.test_request_context(
                            "/validate/check", method="POST",
                            data={"serial": self.token.token.serial, "pass": "testpin" + otp}):
                        response = self.app.full_dispatch_request()
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(response.json["result"]["value"], expected)
                self.assertEqual(self.token.get_failcount(), failcount)
        self.assertEqual(self.token.get_otp_count(), self.first_counter + 2)
        self.assert_pair_cleared()
