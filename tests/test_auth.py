import time
import unittest
from pathlib import Path

from lib.auth import university_user


class AuthPolicyTests(unittest.TestCase):
    def setUp(self):
        self.claims = {
            "sub": "123456789", "email": "student@s.okayama-u.ac.jp",
            "email_verified": True, "hd": "okayama-u.ac.jp", "exp": time.time() + 3600,
        }

    def test_accepts_verified_university_accounts(self):
        user = university_user(self.claims)
        self.assertEqual(user.id, "google:123456789")
        self.assertEqual(user.email, self.claims["email"])
        self.assertIsNotNone(university_user({**self.claims, "email": "Staff@okayama-u.ac.jp"}))

    def test_rejects_invalid_accounts_and_expired_identity(self):
        for change in (
            {"email_verified": False}, {"email_verified": "true"}, {"hd": None},
            {"hd": "example.com"}, {"sub": ""}, {"sub": "id\nInjected: yes"},
            {"email": "user@gmail.com"}, {"email": "user@okayama-u.ac.jp.evil.test"},
            {"email": "user@s.okayama-u.ac.jp@evil.test"}, {"exp": time.time() - 1},
            {"exp": None}, {"exp": True},
        ):
            with self.subTest(change=change):
                self.assertIsNone(university_user({**self.claims, **change}))

    def test_empty_allowlist_denies_access(self):
        self.assertIsNone(university_user(self.claims, email_domains=[]))
        self.assertIsNone(university_user(self.claims, hosted_domains=[]))

    def test_unconfigured_page_stops_at_login(self):
        from streamlit.testing.v1 import AppTest

        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py")).run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.title[0].value, "App")
        self.assertTrue(app.button[0].disabled)


if __name__ == "__main__":
    unittest.main()
