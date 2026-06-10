"""JWT validation behavior and plugin initialization requirements."""

from datetime import timedelta

import pytest

from flask import Flask

from dserver_token_generator_plugin_oauth2.config import JwtConfig
from dserver_token_generator_plugin_oauth2.jwt_utils import JwtTokenGenerator
from dserver_token_generator_plugin_oauth2.plugin import (
    OAuth2TokenGeneratorPlugin,
)


@pytest.fixture
def jwt_generator(rsa_key_files):
    private_path, public_path = rsa_key_files
    config = JwtConfig(
        private_key_file=private_path,
        public_key_file=public_path,
        token_expiry_hours=1,
    )
    return JwtTokenGenerator(config)


def test_valid_token_roundtrip(jwt_generator):
    token = jwt_generator.generate_token("user1", permissions=["search"])
    payload = jwt_generator.verify_token(token)
    assert payload is not None
    assert payload["sub"] == "user1"
    assert payload["permissions"] == ["search"]


def test_expired_token_rejected(jwt_generator):
    jwt_generator.config.token_expiry_hours = -1  # already expired
    token = jwt_generator.generate_token("user1")
    assert jwt_generator.verify_token(token) is None


def test_wrong_audience_rejected(jwt_generator, rsa_key_files):
    private_path, public_path = rsa_key_files
    other = JwtTokenGenerator(JwtConfig(
        private_key_file=private_path,
        public_key_file=public_path,
        audience="someone-else",
    ))
    token = other.generate_token("user1")
    assert jwt_generator.verify_token(token) is None


def test_tampered_token_rejected(jwt_generator):
    token = jwt_generator.generate_token("user1")
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert jwt_generator.verify_token(tampered) is None


# --- SECRET_KEY enforcement -----------------------------------------------

def test_init_app_requires_secret_key_outside_development():
    app = Flask(__name__)
    assert not app.config.get("SECRET_KEY")
    plugin = OAuth2TokenGeneratorPlugin()
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        plugin.init_app(app)


def test_init_app_allows_missing_secret_key_in_development():
    app = Flask(__name__)
    app.config["FLASK_ENV"] = "development"
    plugin = OAuth2TokenGeneratorPlugin()
    plugin.init_app(app)  # warning only


def test_init_app_with_secret_key():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "configured"
    plugin = OAuth2TokenGeneratorPlugin()
    plugin.init_app(app)
