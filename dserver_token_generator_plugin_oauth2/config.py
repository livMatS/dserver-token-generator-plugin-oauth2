"""
Configuration management for OAuth2 integration.

This module handles loading and validating OAuth2 configuration
for integration with various identity providers.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class OAuth2ProviderConfig:
    """OAuth2 Identity Provider configuration."""

    # Provider identification
    name: str = "oauth2"

    # OAuth2 endpoints
    authorization_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""  # Optional, for OIDC providers

    # Client credentials
    client_id: str = ""
    client_secret: str = ""

    # OAuth2 settings
    scope: str = "openid"
    response_type: str = "code"

    # Callback URL (constructed from base URL)
    redirect_uri: str = ""

    # User attribute mapping (provider field -> internal field)
    # These map the OAuth2/OIDC userinfo response to internal user fields
    attribute_map: dict = field(default_factory=lambda: {
        "sub": "user_id",
        "email": "email",
        "name": "display_name",
        "given_name": "given_name",
        "family_name": "surname",
    })

    # Field to use as username (from attribute_map values)
    username_field: str = "user_id"

    @classmethod
    def from_env(cls) -> "OAuth2ProviderConfig":
        """Create configuration from environment variables."""
        base_url = os.environ.get("OAUTH2_BASE_URL", "http://localhost:5000")

        # Parse attribute map from env if provided
        # Format: "sub:user_id,email:email,name:display_name"
        attribute_map_str = os.environ.get("OAUTH2_ATTRIBUTE_MAP", "")
        if attribute_map_str:
            attribute_map = {}
            for mapping in attribute_map_str.split(","):
                if ":" in mapping:
                    key, value = mapping.split(":", 1)
                    attribute_map[key.strip()] = value.strip()
        else:
            # Default attribute map
            attribute_map = {
                "sub": "user_id",
                "email": "email",
                "name": "display_name",
                "given_name": "given_name",
                "family_name": "surname",
            }

        return cls(
            name=os.environ.get("OAUTH2_PROVIDER_NAME", "oauth2"),
            authorization_url=os.environ.get("OAUTH2_AUTHORIZATION_URL", ""),
            token_url=os.environ.get("OAUTH2_TOKEN_URL", ""),
            userinfo_url=os.environ.get("OAUTH2_USERINFO_URL", ""),
            client_id=os.environ.get("OAUTH2_CLIENT_ID", ""),
            client_secret=os.environ.get("OAUTH2_CLIENT_SECRET", ""),
            scope=os.environ.get("OAUTH2_SCOPE", "openid"),
            response_type=os.environ.get("OAUTH2_RESPONSE_TYPE", "code"),
            redirect_uri=os.environ.get(
                "OAUTH2_REDIRECT_URI",
                f"{base_url}/auth/callback"
            ),
            attribute_map=attribute_map,
            username_field=os.environ.get("OAUTH2_USERNAME_FIELD", "user_id"),
        )


@dataclass
class JwtConfig:
    """JWT token configuration."""

    private_key_file: str = "/app/jwt/jwt_key"
    public_key_file: str = "/app/jwt/jwt_key.pub"
    algorithm: str = "RS256"
    issuer: str = "dserver"
    audience: str = "dserver"
    token_expiry_hours: int = 24

    @classmethod
    def from_env(cls) -> "JwtConfig":
        """Create configuration from environment variables."""
        return cls(
            private_key_file=os.environ.get(
                "JWT_PRIVATE_KEY_FILE", "/app/jwt/jwt_key"
            ),
            public_key_file=os.environ.get(
                "JWT_PUBLIC_KEY_FILE", "/app/jwt/jwt_key.pub"
            ),
            algorithm=os.environ.get("JWT_ALGORITHM", "RS256"),
            issuer=os.environ.get("JWT_ISSUER", "dserver"),
            audience=os.environ.get("JWT_AUDIENCE", "dserver"),
            token_expiry_hours=int(os.environ.get("JWT_TOKEN_EXPIRY_HOURS", "24")),
        )


@dataclass
class PluginConfig:
    """Overall plugin configuration."""

    oauth2: OAuth2ProviderConfig = field(default_factory=OAuth2ProviderConfig.from_env)
    jwt: JwtConfig = field(default_factory=JwtConfig.from_env)

    # Base URL for constructing callback URLs
    base_url: str = "http://localhost:5000"

    # User provisioning settings
    auto_provision_users: bool = True
    default_user_permissions: list = field(default_factory=lambda: ["search", "retrieve"])

    # Frontend redirect settings
    frontend_url: str = "/"
    login_success_redirect: str = "/"
    login_error_redirect: str = "/login?error=auth_failed"

    @classmethod
    def from_env(cls) -> "PluginConfig":
        """Create configuration from environment variables."""
        return cls(
            oauth2=OAuth2ProviderConfig.from_env(),
            jwt=JwtConfig.from_env(),
            base_url=os.environ.get("OAUTH2_BASE_URL", "http://localhost:5000"),
            auto_provision_users=os.environ.get(
                "OAUTH2_AUTO_PROVISION_USERS", "true"
            ).lower() == "true",
            default_user_permissions=os.environ.get(
                "OAUTH2_DEFAULT_USER_PERMISSIONS", "search,retrieve"
            ).split(","),
            frontend_url=os.environ.get("OAUTH2_FRONTEND_URL", "/"),
            login_success_redirect=os.environ.get(
                "OAUTH2_LOGIN_SUCCESS_REDIRECT", "/"
            ),
            login_error_redirect=os.environ.get(
                "OAUTH2_LOGIN_ERROR_REDIRECT", "/login?error=auth_failed"
            ),
        )


# Pre-configured provider templates
PROVIDER_PRESETS = {
    "orcid": {
        "name": "orcid",
        "authorization_url": "https://orcid.org/oauth/authorize",
        "token_url": "https://orcid.org/oauth/token",
        "userinfo_url": "",  # ORCID returns user info in token response
        "scope": "/authenticate",
        "attribute_map": {
            "orcid": "user_id",
            "name": "display_name",
        },
        "username_field": "user_id",
    },
    "orcid_sandbox": {
        "name": "orcid_sandbox",
        "authorization_url": "https://sandbox.orcid.org/oauth/authorize",
        "token_url": "https://sandbox.orcid.org/oauth/token",
        "userinfo_url": "",
        "scope": "/authenticate",
        "attribute_map": {
            "orcid": "user_id",
            "name": "display_name",
        },
        "username_field": "user_id",
    },
    "github": {
        "name": "github",
        "authorization_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
        "attribute_map": {
            "id": "user_id",
            "login": "username",
            "email": "email",
            "name": "display_name",
        },
        "username_field": "username",
    },
    "google": {
        "name": "google",
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
        "attribute_map": {
            "sub": "user_id",
            "email": "email",
            "name": "display_name",
            "given_name": "given_name",
            "family_name": "surname",
        },
        "username_field": "email",
    },
}


def get_provider_preset(name: str) -> dict:
    """Get a provider preset configuration by name."""
    return PROVIDER_PRESETS.get(name.lower(), {})
