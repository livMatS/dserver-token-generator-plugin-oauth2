"""Tests for JWT token generation utilities."""

import tempfile
from pathlib import Path

import pytest

from dserver_token_generator_plugin_oauth2.jwt_utils import JwtTokenGenerator
from dserver_token_generator_plugin_oauth2.config import JwtConfig


# Test RSA keys (DO NOT USE IN PRODUCTION)
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MvXJMVHTkHmMWWvF
NQKyTDMHC9OCXqPNhjBpJOHQvQpELMDnMA3gVYVjuMDkDh7DPmLGhUIc1qSbqA0I
kHmpVKaNBHRIEuOz6wCbiUlbXn5KzQzOh1IbACFP0hn7eHRXHT8ZlK5O1cPPH8Dy
Z0YRU9hU0G4ZXCbDjGGj0WdPx2XEu5bZOL8NSKfnJv1BPVZQ1JHXcLCqm6oHqABY
PEYbTvxsAlJCPtLnmOCPBPXjLqhSKHf3TGVe9YcJJdLxhmYWw9lVvT1FXrlP6Yb5
B4cLVMp/cQgXKT1dLq2WKkXQFVoZKfKJjPv7GQIDAQABAoIBAC3DVClviIpz/tOL
ZdrdKxSFn5GPJ/hNv6uT4hz3hUqH+rBf0NKW4QSTjQtZ8RX6h8H3E3qFihX0aXGp
Jy1kgNQnaJj6p+0QYfg1NMU1HxEpMvTGYdMGrHzrPMlJz3E7zKc9hLxq1c7Tjxxj
DcnZgDOJXj0l7BNkxbU/rPkPl7E8x5rMmPMHFG8W2cFTOPvKWBKK8hLEGhGgaJoB
qleOHr5dDFV0FO4TdV53YzEPMIYbOXNdCLcHG/Qk4B5VwGUGD8M+e8y5LLY3OFXJ
L7YH+w/EJU7HWMI9zWu1wPU+EwrL5Z3k7IL9AGIQLS+xMOT0Q29YCJBZ1c7S2lWX
EpPQ7AECgYEA7sCP7s7MwjH9JS7w0LSL0wFr0Q0+R9YZFHB1EZlEaxGL7xqOxY/2
A2sP5IWHJlTe0PjKNz/k7Hxo3WXls3FVeZQ/DYSQPLT3z7HqoI/xqJ/GbNVPWvJD
6+z4PFXD7dVOlv8kZT5F0N1m5KYg8f9TKy7sPxXnPQ7B5gI0O8Tnp8ECgYEA4GOX
0nE8TR1VVIX3b2yFJmLI8bPFdPTz9HDRxQ7Dd0lBxNz5EhPRLcOu7JmJgEqD2cOJ
pQDJDl3pPuzsg+6E/v//ydMn0ALBPVI9sljTMgWXudJPDSv7MkJV0b7o3w8cPfPJ
OPy2l5LbNU7Mn26fMFt5LrLGI1T9Tp+hQQILqskCgYEA1iYqmF3HkZ3s/CLhDJA+
S3L+sJi7JTQO3y8CBBBsy7DPn7+IPKvGz8W5K3L7LpmGPgL9N3OkPNsEqE+P8mFn
D2aYJIdMH/y0WJlv0SlDz2N5GXBr7tCzq8gYIC9qLfmwIGJo3QZLbbhALLzfxaCn
9d3k0BAtKXJZD0JejPo6r8ECgYBzOPn2dVJzLnMQsJN0OpxgPKJpTxTqTBGxr0YK
O8c/TnazLf9MJPJ+eb0X+PVz5M6cH3E7g7o1e5WiJzLeCIqd/Vq7rGBnAQAqVVj1
K8oOp5K+VPH+sKHw0IqJW7Dj3YE5MmrCmQOgGQ2DFHEL6Wo7EWmEBU6xBzcGqeps
D1PHiQKBgQCyUdD2dJOJpLC0lKc7PMfE9k0cP/K3oDYwpJF4FLKzZ9D/Lmjob3BJ
d+n3bwtIIi+L0hnFEVcQ5L0BMnJdGKt/F8J8VHULfxT+X/bCXjjNBT0K7J8OSNmJ
tV9Dt7BbVsqXE3cDaLSvNcU9NqJrJgqVGWk4JXny8fPDKoxHgxnDBw==
-----END RSA PRIVATE KEY-----"""

TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWy
F8PbnGy0AHB7MvXJMVHTkHmMWWvFNQKyTDMHC9OCXqPNhjBpJOHQvQpELMDnMA3g
VYVjuMDkDh7DPmLGhUIc1qSbqA0IkHmpVKaNBHRIEuOz6wCbiUlbXn5KzQzOh1Ib
ACFP0hn7eHRXHT8ZlK5O1cPPH8DyZ0YRU9hU0G4ZXCbDjGGj0WdPx2XEu5bZOL8N
SKfnJv1BPVZQ1JHXcLCqm6oHqABYPEYbTvxsAlJCPtLnmOCPBPXjLqhSKHf3TGVe
9YcJJdLxhmYWw9lVvT1FXrlP6Yb5B4cLVMp/cQgXKT1dLq2WKkXQFVoZKfKJjPv7
GQIDAQAB
-----END PUBLIC KEY-----"""


@pytest.fixture
def temp_keys():
    """Create temporary key files for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        private_key_path = Path(tmpdir) / "jwt_key"
        public_key_path = Path(tmpdir) / "jwt_key.pub"
        private_key_path.write_text(TEST_PRIVATE_KEY)
        public_key_path.write_text(TEST_PUBLIC_KEY)
        yield str(private_key_path), str(public_key_path)


@pytest.fixture
def jwt_config(temp_keys):
    """Create JWT configuration with test keys."""
    private_key_path, public_key_path = temp_keys
    return JwtConfig(
        private_key_file=private_key_path,
        public_key_file=public_key_path,
        algorithm="RS256",
        issuer="test-issuer",
        audience="test-audience",
        token_expiry_hours=1,
    )


@pytest.fixture
def jwt_generator(jwt_config):
    """Create JWT token generator."""
    return JwtTokenGenerator(jwt_config)


class TestJwtTokenGenerator:
    """Test cases for JwtTokenGenerator."""

    def test_generate_token(self, jwt_generator):
        """Test basic token generation."""
        token = jwt_generator.generate_token(
            username="test@example.com",
            email="test@example.com",
            display_name="Test User",
        )
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_token_with_permissions(self, jwt_generator):
        """Test token generation with permissions."""
        token = jwt_generator.generate_token(
            username="test@example.com",
            permissions=["search", "retrieve", "admin"],
        )
        claims = jwt_generator.verify_token(token)
        assert claims is not None
        assert claims["permissions"] == ["search", "retrieve", "admin"]

    def test_verify_valid_token(self, jwt_generator):
        """Test verification of valid token."""
        token = jwt_generator.generate_token(username="test@example.com")
        claims = jwt_generator.verify_token(token)
        assert claims is not None
        assert claims["username"] == "test@example.com"
        assert claims["iss"] == "test-issuer"
        assert claims["aud"] == "test-audience"

    def test_verify_invalid_token(self, jwt_generator):
        """Test verification of invalid token."""
        claims = jwt_generator.verify_token("invalid.token.here")
        assert claims is None

    def test_verify_tampered_token(self, jwt_generator):
        """Test verification of tampered token."""
        token = jwt_generator.generate_token(username="test@example.com")
        tampered = token[:-5] + "xxxxx"
        claims = jwt_generator.verify_token(tampered)
        assert claims is None

    def test_refresh_token(self, jwt_generator):
        """Test token refresh."""
        original_token = jwt_generator.generate_token(
            username="test@example.com",
            email="test@example.com",
        )
        new_token = jwt_generator.refresh_token(original_token)
        assert new_token is not None
        assert new_token != original_token
        claims = jwt_generator.verify_token(new_token)
        assert claims["username"] == "test@example.com"

    def test_refresh_invalid_token(self, jwt_generator):
        """Test refresh of invalid token."""
        new_token = jwt_generator.refresh_token("invalid.token.here")
        assert new_token is None

    def test_token_contains_standard_claims(self, jwt_generator):
        """Test that token contains all standard JWT claims."""
        token = jwt_generator.generate_token(username="test@example.com")
        claims = jwt_generator.verify_token(token)
        for claim in ("iss", "aud", "sub", "iat", "exp", "nbf", "username"):
            assert claim in claims
