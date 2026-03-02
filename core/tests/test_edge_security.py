"""
Tests for edge routing security — secret redaction in LLM prompts.

Validates that _sanitize_memory_for_prompt() prevents credential/PII
leakage when shared memory is injected into LLM routing prompts.
"""


from framework.graph.edge import _sanitize_memory_for_prompt


class TestSanitizeMemoryForPrompt:
    """Verify secret redaction before LLM prompt injection."""

    def test_api_key_redacted(self):
        memory = {"api_key": "sk-secret-12345", "status": "ready"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["api_key"] == "[REDACTED]"
        assert result["status"] == "ready"

    def test_access_token_redacted(self):
        memory = {"access_token": "ghp_xxxxxxxxxxxx"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["access_token"] == "[REDACTED]"

    def test_refresh_token_redacted(self):
        memory = {"refresh_token": "rt_xxxxxxxxxxxx"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["refresh_token"] == "[REDACTED]"

    def test_password_redacted(self):
        memory = {"database_password": "hunter2"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["database_password"] == "[REDACTED]"

    def test_secret_redacted(self):
        memory = {"client_secret": "cs_xxx"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["client_secret"] == "[REDACTED]"

    def test_credential_redacted(self):
        memory = {"user_credential": "cred_xxx"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["user_credential"] == "[REDACTED]"

    def test_bearer_redacted(self):
        memory = {"bearer_value": "eyJhbGciOi..."}
        result = _sanitize_memory_for_prompt(memory)
        assert result["bearer_value"] == "[REDACTED]"

    def test_auth_redacted(self):
        memory = {"auth_header": "Basic dXNlcjpwYXNz"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["auth_header"] == "[REDACTED]"

    def test_case_insensitive_matching(self):
        """Key matching must be case-insensitive."""
        memory = {"API_KEY": "sk-xxx", "Access_Token": "tok-xxx"}
        result = _sanitize_memory_for_prompt(memory)
        assert result["API_KEY"] == "[REDACTED]"
        assert result["Access_Token"] == "[REDACTED]"

    def test_safe_keys_pass_through(self):
        """Non-sensitive keys should pass through with truncation."""
        memory = {
            "customer_name": "Alice",
            "status": "processing",
            "confidence": "0.95",
        }
        result = _sanitize_memory_for_prompt(memory)
        assert result["customer_name"] == "Alice"
        assert result["status"] == "processing"
        assert result["confidence"] == "0.95"

    def test_value_truncation(self):
        """Long values should be truncated to 100 chars."""
        memory = {"description": "x" * 200}
        result = _sanitize_memory_for_prompt(memory)
        assert len(result["description"]) == 100

    def test_max_keys_limit(self):
        """Only max_keys entries should appear in the result."""
        memory = {f"field_{i}": f"value_{i}" for i in range(20)}
        result = _sanitize_memory_for_prompt(memory, max_keys=3)
        assert len(result) == 3

    def test_empty_memory(self):
        result = _sanitize_memory_for_prompt({})
        assert result == {}

    def test_mixed_safe_and_sensitive(self):
        """Mix of safe and sensitive keys."""
        memory = {
            "task": "process invoice",
            "api_key": "sk-super-secret",
            "result": "invoice #123",
            "oauth_token": "tok-yyy",
        }
        result = _sanitize_memory_for_prompt(memory)
        assert result["task"] == "process invoice"
        assert result["api_key"] == "[REDACTED]"
        assert result["result"] == "invoice #123"
        assert result["oauth_token"] == "[REDACTED]"
