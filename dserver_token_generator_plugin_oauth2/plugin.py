"""
dserver plugin registration for OAuth2 token generator.

This module provides the plugin class that integrates with dservercore's
plugin discovery system via the ExtensionABC interface.
"""

import logging

from flask import Flask

from .blueprint import oauth2_bp
from .config import PluginConfig

logger = logging.getLogger(__name__)


class OAuth2TokenGeneratorPlugin:
    """
    OAuth2 Token Generator Plugin for dserver.

    This plugin provides OAuth 2.0 authentication for users via any
    OAuth2/OIDC compliant Identity Provider and issues JWT tokens.

    Implements the dservercore ExtensionABC interface.
    """

    def __init__(self, app: Flask = None):
        """
        Initialize the plugin.

        Args:
            app: Flask application instance (optional, can call init_app later)
        """
        self.app = app
        self.config: PluginConfig = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask, *args, **kwargs):
        """
        Initialize the plugin with a Flask application.

        This is called by dservercore's app factory.

        Args:
            app: Flask application instance
        """
        self.app = app

        # Load configuration
        self.config = PluginConfig.from_env()

        # Configure Flask session
        if not app.config.get("SECRET_KEY"):
            logger.warning(
                "Flask SECRET_KEY not set. Sessions will not persist across restarts."
            )

        logger.debug(f"Session config: SECURE={app.config.get('SESSION_COOKIE_SECURE')}, "
                    f"SAMESITE={app.config.get('SESSION_COOKIE_SAMESITE')}")

        logger.info("OAuth2 Token Generator plugin initialized")
        logger.info(f"OAuth2 Provider: {self.config.oauth2.name}")
        if self.config.oauth2.authorization_url:
            logger.info(f"Authorization URL: {self.config.oauth2.authorization_url}")
        else:
            logger.warning("OAuth2 not fully configured - OAUTH2_AUTHORIZATION_URL not set")

    def get_blueprint(self):
        """
        Return the Flask blueprint for this extension.

        Required by dservercore ExtensionABC.
        """
        return oauth2_bp

    def register_dataset(self, dataset_info):
        """
        Register a dataset (no-op for auth plugin).

        Required by dservercore PluginABC but not used for authentication.
        """
        pass

    def get_config(self):
        """
        Return plugin configuration dictionary.

        Required by dservercore PluginABC.
        This is loaded BEFORE init_app, so session settings go here.
        """
        return {
            # Session cookie settings for OAuth2 flow
            # SECURE must be False for HTTP (dev), True for HTTPS (prod)
            # SAMESITE must be "Lax" for OAuth2 redirects to work
            "SESSION_COOKIE_SECURE": False,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
        }

    def get_config_secrets_to_obfuscate(self):
        """Return config keys that should not be exposed."""
        return ["OAUTH2_CLIENT_SECRET"]

    @staticmethod
    def get_name() -> str:
        """Return the plugin name."""
        return "oauth2-token-generator"

    @staticmethod
    def get_version() -> str:
        """Return the plugin version."""
        from . import __version__
        return __version__

    @staticmethod
    def get_description() -> str:
        """Return the plugin description."""
        return "OAuth 2.0 token generator for dserver"
