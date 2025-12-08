"""
dserver plugin registration for OAuth2 token generator.

This module provides the plugin class that integrates with dservercore's
plugin discovery system.
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

    def init_app(self, app: Flask):
        """
        Initialize the plugin with a Flask application.

        This registers the blueprint and configures the plugin.

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

        # Ensure session cookie settings are secure
        app.config.setdefault("SESSION_COOKIE_SECURE", True)
        app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
        app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

        # Register the blueprint
        app.register_blueprint(oauth2_bp)

        logger.info("OAuth2 Token Generator plugin initialized")
        logger.info(f"OAuth2 Provider: {self.config.oauth2.name}")
        if self.config.oauth2.authorization_url:
            logger.info(f"Authorization URL: {self.config.oauth2.authorization_url}")
        else:
            logger.warning("OAuth2 not fully configured - OAUTH2_AUTHORIZATION_URL not set")

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
