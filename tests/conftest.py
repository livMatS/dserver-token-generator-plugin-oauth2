"""Test fixtures for the OAuth2 token generator plugin."""

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask

import dserver_token_generator_plugin_oauth2.blueprint as bp_module
from dserver_token_generator_plugin_oauth2.blueprint import oauth2_bp

FRONTEND = "http://127.0.0.1:8080"


@pytest.fixture
def rsa_key_files(tmp_path):
    """Generate an RSA key pair and return (private_path, public_path)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = tmp_path / "jwt_key"
    public_path = tmp_path / "jwt_key.pub"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return str(private_path), str(public_path)


@pytest.fixture
def app(monkeypatch, rsa_key_files):
    private_path, public_path = rsa_key_files
    monkeypatch.setenv(
        "OAUTH2_AUTHORIZATION_URL", "https://provider.example/authorize")
    monkeypatch.setenv("OAUTH2_TOKEN_URL", "https://provider.example/token")
    monkeypatch.delenv("OAUTH2_USERINFO_URL", raising=False)
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "client-id")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("OAUTH2_FRONTEND_URL", FRONTEND)
    monkeypatch.setenv("OAUTH2_LOGIN_SUCCESS_REDIRECT", f"{FRONTEND}/")
    monkeypatch.setenv(
        "OAUTH2_LOGIN_ERROR_REDIRECT", f"{FRONTEND}/login?error=auth_failed")
    monkeypatch.setenv("JWT_PRIVATE_KEY_FILE", private_path)
    monkeypatch.setenv("JWT_PUBLIC_KEY_FILE", public_path)

    # Reset module-level config caches so env vars take effect per test.
    monkeypatch.setattr(bp_module, "_config", None)
    monkeypatch.setattr(bp_module, "_jwt_generator", None)
    monkeypatch.setattr(bp_module, "_user_provisioner", None)

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "test-secret"
    app.config["TESTING"] = True
    app.register_blueprint(oauth2_bp)
    return app


@pytest.fixture
def client(app):
    return app.test_client()
