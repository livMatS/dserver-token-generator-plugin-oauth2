"""Tests for OAuth2 plugin configuration."""

import pytest
from dserver_token_generator_plugin_oauth2.config import (
    JwtConfig,
    OAuth2ProviderConfig,
    PluginConfig,
    get_provider_preset,
    PROVIDER_PRESETS,
)


class TestJwtConfig:
    def test_defaults(self):
        config = JwtConfig()
        assert config.algorithm == "RS256"
        assert config.issuer == "dserver"
        assert config.audience == "dserver"
        assert config.token_expiry_hours == 24

    def test_from_env_defaults(self, monkeypatch):
        for key in ["JWT_ALGORITHM", "JWT_ISSUER", "JWT_AUDIENCE", "JWT_TOKEN_EXPIRY_HOURS",
                    "JWT_PRIVATE_KEY_FILE", "JWT_PUBLIC_KEY_FILE"]:
            monkeypatch.delenv(key, raising=False)
        config = JwtConfig.from_env()
        assert config.algorithm == "RS256"
        assert config.issuer == "dserver"
        assert config.token_expiry_hours == 24

    def test_from_env_override(self, monkeypatch):
        monkeypatch.setenv("JWT_ISSUER", "myserver")
        monkeypatch.setenv("JWT_TOKEN_EXPIRY_HOURS", "48")
        config = JwtConfig.from_env()
        assert config.issuer == "myserver"
        assert config.token_expiry_hours == 48


class TestOAuth2ProviderConfig:
    def test_defaults(self):
        config = OAuth2ProviderConfig()
        assert config.name == "oauth2"
        assert config.scope == "openid"
        assert "sub" in config.attribute_map
        assert config.username_field == "user_id"

    def test_from_env_defaults(self, monkeypatch):
        for key in ["OAUTH2_PROVIDER_NAME", "OAUTH2_CLIENT_ID", "OAUTH2_SCOPE",
                    "OAUTH2_ATTRIBUTE_MAP"]:
            monkeypatch.delenv(key, raising=False)
        config = OAuth2ProviderConfig.from_env()
        assert config.scope == "openid"

    def test_attribute_map_from_env(self, monkeypatch):
        monkeypatch.setenv("OAUTH2_ATTRIBUTE_MAP", "sub:user_id,email:email")
        config = OAuth2ProviderConfig.from_env()
        assert config.attribute_map == {"sub": "user_id", "email": "email"}

    def test_attribute_map_ignores_malformed_entries(self, monkeypatch):
        monkeypatch.setenv("OAUTH2_ATTRIBUTE_MAP", "sub:user_id,badentry,email:email")
        config = OAuth2ProviderConfig.from_env()
        assert "sub" in config.attribute_map
        assert "email" in config.attribute_map


class TestPluginConfig:
    def test_from_env_defaults(self, monkeypatch):
        for key in ["OAUTH2_BASE_URL", "OAUTH2_AUTO_PROVISION_USERS",
                    "OAUTH2_FRONTEND_URL"]:
            monkeypatch.delenv(key, raising=False)
        config = PluginConfig.from_env()
        assert config.base_url == "http://localhost:5000"
        assert config.frontend_url == "/"


class TestProviderPresets:
    def test_orcid_preset(self):
        preset = get_provider_preset("orcid")
        assert preset["name"] == "orcid"
        assert "orcid.org" in preset["authorization_url"]

    def test_github_preset(self):
        preset = get_provider_preset("github")
        assert preset["name"] == "github"
        assert "github.com" in preset["authorization_url"]

    def test_google_preset(self):
        preset = get_provider_preset("google")
        assert preset["name"] == "google"
        assert "google" in preset["authorization_url"]

    def test_unknown_preset_returns_empty(self):
        preset = get_provider_preset("nonexistent_provider")
        assert preset == {}

    def test_case_insensitive(self):
        preset = get_provider_preset("ORCID")
        assert preset["name"] == "orcid"

    def test_all_presets_have_required_keys(self):
        required_keys = {"name", "authorization_url", "token_url", "attribute_map",
                         "username_field"}
        for name, preset in PROVIDER_PRESETS.items():
            for key in required_keys:
                assert key in preset, f"Preset '{name}' missing key '{key}'"
