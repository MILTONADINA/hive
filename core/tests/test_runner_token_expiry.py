"""Tests for expired token handling in get_claude_code_token / get_codex_token.

Verifies that expired tokens are NOT silently returned when refresh fails.
Instead, None is returned so callers see a clear auth failure rather than
wasting LLM retry budget on 401/403 errors.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from framework.runner.runner import get_claude_code_token, get_codex_token


def _make_claude_creds(*, expired: bool = False, refresh_token: str | None = "refresh-tok") -> dict:
    """Build a mock Claude credentials dict."""
    now_ms = int(time.time() * 1000)
    expires_at = now_ms - 60_000 if expired else now_ms + 600_000
    oauth: dict = {"accessToken": "old-access-tok", "expiresAt": expires_at}
    if refresh_token is not None:
        oauth["refreshToken"] = refresh_token
    return {"claudeAiOauth": oauth}


def _make_codex_auth(*, expired: bool = False, refresh_token: str | None = "refresh-tok") -> dict:
    """Build a mock Codex auth dict."""
    now_s = time.time()
    expires_at = now_s - 60 if expired else now_s + 600
    tokens: dict = {"access_token": "old-codex-tok"}
    if refresh_token is not None:
        tokens["refresh_token"] = refresh_token
    return {"tokens": tokens, "expires_at": expires_at}


# ---------------------------------------------------------------------------
# Claude Code token tests
# ---------------------------------------------------------------------------


class TestClaudeCodeTokenExpiry:
    def test_valid_token_returned(self):
        """Non-expired token should be returned as-is."""
        creds = _make_claude_creds(expired=False)
        with patch("framework.runner.runner._read_claude_credentials", return_value=creds):
            assert get_claude_code_token() == "old-access-tok"

    def test_expired_no_refresh_returns_none(self):
        """Expired token with no refresh token should return None."""
        creds = _make_claude_creds(expired=True, refresh_token=None)
        with patch("framework.runner.runner._read_claude_credentials", return_value=creds):
            result = get_claude_code_token()
            assert result is None

    def test_expired_refresh_fails_returns_none(self):
        """Expired token where refresh fails should return None."""
        creds = _make_claude_creds(expired=True)
        with (
            patch("framework.runner.runner._read_claude_credentials", return_value=creds),
            patch("framework.runner.runner._refresh_claude_code_token", return_value=None),
        ):
            result = get_claude_code_token()
            assert result is None

    def test_expired_refresh_succeeds(self):
        """Expired token where refresh succeeds should return new token."""
        creds = _make_claude_creds(expired=True)
        new_tokens = {"access_token": "new-access-tok", "expires_in": 3600}
        with (
            patch("framework.runner.runner._read_claude_credentials", return_value=creds),
            patch("framework.runner.runner._refresh_claude_code_token", return_value=new_tokens),
            patch("framework.runner.runner._save_refreshed_credentials"),
        ):
            result = get_claude_code_token()
            assert result == "new-access-tok"

    def test_no_credentials_returns_none(self):
        """No credentials at all should return None."""
        with patch("framework.runner.runner._read_claude_credentials", return_value=None):
            assert get_claude_code_token() is None


# ---------------------------------------------------------------------------
# Codex token tests
# ---------------------------------------------------------------------------


class TestCodexTokenExpiry:
    def test_valid_token_returned(self):
        """Non-expired token should be returned as-is."""
        auth = _make_codex_auth(expired=False)
        with (
            patch("framework.runner.runner._read_codex_keychain", return_value=None),
            patch("framework.runner.runner._read_codex_auth_file", return_value=auth),
            patch("framework.runner.runner._is_codex_token_expired", return_value=False),
        ):
            assert get_codex_token() == "old-codex-tok"

    def test_expired_no_refresh_returns_none(self):
        """Expired token with no refresh token should return None."""
        auth = _make_codex_auth(expired=True, refresh_token=None)
        with (
            patch("framework.runner.runner._read_codex_keychain", return_value=None),
            patch("framework.runner.runner._read_codex_auth_file", return_value=auth),
            patch("framework.runner.runner._is_codex_token_expired", return_value=True),
        ):
            result = get_codex_token()
            assert result is None

    def test_expired_refresh_fails_returns_none(self):
        """Expired token where refresh fails should return None."""
        auth = _make_codex_auth(expired=True)
        with (
            patch("framework.runner.runner._read_codex_keychain", return_value=None),
            patch("framework.runner.runner._read_codex_auth_file", return_value=auth),
            patch("framework.runner.runner._is_codex_token_expired", return_value=True),
            patch("framework.runner.runner._refresh_codex_token", return_value=None),
        ):
            result = get_codex_token()
            assert result is None

    def test_expired_refresh_succeeds(self):
        """Expired token where refresh succeeds should return new token."""
        auth = _make_codex_auth(expired=True)
        new_tokens = {"access_token": "new-codex-tok", "expires_in": 3600}
        with (
            patch("framework.runner.runner._read_codex_keychain", return_value=None),
            patch("framework.runner.runner._read_codex_auth_file", return_value=auth),
            patch("framework.runner.runner._is_codex_token_expired", return_value=True),
            patch("framework.runner.runner._refresh_codex_token", return_value=new_tokens),
            patch("framework.runner.runner._save_refreshed_codex_credentials"),
        ):
            result = get_codex_token()
            assert result == "new-codex-tok"
