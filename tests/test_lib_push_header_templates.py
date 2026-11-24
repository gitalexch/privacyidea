# SPDX-License-Identifier: AGPL-3.0-or-later

"""Request-header substitutions in PUSH notification text."""

from types import SimpleNamespace
from unittest import TestCase, mock

from werkzeug.datastructures import EnvironHeaders

from privacyidea.lib.tokens import pushtoken as push


class PushHeaderTemplateTestCase(TestCase):
    def render(self, template, headers=None, triggering_request=True, with_context=True):
        environ = dict(headers or {})
        request = SimpleNamespace(headers=EnvironHeaders(environ))
        if triggering_request:
            request.User = None
        environ["werkzeug.request"] = request
        options = {"g": SimpleNamespace(request_headers=request.headers)} if with_context else {}
        token = SimpleNamespace(token=SimpleNamespace(serial="PUSH-HEADER-TEST"), user=None)
        tags = {"username": "alice", "ua_string": "Keycloak/1.0",
                "ua_browser": "Keycloak", "action": "/validate/check"}

        def policy_value(scope, action, options):
            return template if action == push.PushAction.MOBILE_TEXT else None

        with mock.patch.object(push, "get_action_values_from_options", side_effect=policy_value), \
                mock.patch.object(push, "create_tag_dict", return_value=tags):
            return push._build_mobile_notification(token, options)

    def test_wsgi_header_reaches_the_notification(self):
        result = self.render("Login to {request_headers[X-Application]}",
                             {"HTTP_X_APPLICATION": "Payroll"})
        self.assertEqual("Login to Payroll", result["question"])
        self.assertEqual("privacyIDEA", result["title"])

    def test_header_names_are_case_insensitive(self):
        for name in ("X-Application", "x-application", "X-APPLICATION"):
            with self.subTest(name=name):
                result = self.render("App {request_headers[" + name + "]}",
                                     {"HTTP_X_APPLICATION": "Payroll"})
                self.assertEqual("App Payroll", result["question"])

    def test_missing_header_does_not_discard_other_text(self):
        result = self.render("User {username}, app [{request_headers[X-Missing]}]",
                             {"HTTP_USER_AGENT": "Keycloak/1.0"})
        self.assertEqual("User alice, app []", result["question"])

    def test_missing_context_produces_empty_header_values(self):
        result = self.render("App [{request_headers[X-Application]}]", with_context=False)
        self.assertEqual("App []", result["question"])

    def test_polling_headers_are_not_used_as_triggering_headers(self):
        result = self.render("App [{request_headers[X-Application]}]",
                             {"HTTP_X_APPLICATION": "Smartphone"}, triggering_request=False)
        self.assertEqual("App []", result["question"])

    def test_header_values_are_not_formatted_again(self):
        value = "+15555550123 {username}"
        result = self.render("Phone {request_headers[X-Phone]}", {"HTTP_X_PHONE": value})
        self.assertEqual("Phone " + value, result["question"])

    def test_each_header_value_is_capped(self):
        result = self.render("{request_headers[X-Application]}",
                             {"HTTP_X_APPLICATION": "x" * 8000})
        self.assertEqual("x" * push.MAX_CLIENT_TAG_LENGTH, result["question"])

    def test_numeric_header_names_work(self):
        result = self.render("App {request_headers[123]}", {"HTTP_123": "Payroll"})
        self.assertEqual("App Payroll", result["question"])

    def test_existing_tags_keep_their_behavior(self):
        result = self.render("{username}: {ua_browser} ({ua_string}) at {action}")
        self.assertEqual("alice: Keycloak (Keycloak/1.0) at /validate/check", result["question"])

    def test_unknown_top_level_tags_keep_the_default_text(self):
        result = self.render("Unknown {not_a_tag}")
        self.assertEqual(str(push.DEFAULT_MOBILE_TEXT), result["question"])
