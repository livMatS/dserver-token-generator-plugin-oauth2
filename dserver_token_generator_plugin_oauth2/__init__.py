"""
dserver-token-generator-plugin-oauth2

A generic OAuth 2.0 token generator plugin for dserver that integrates with
any OAuth 2.0 / OpenID Connect compliant Identity Provider.

Supported providers include:
- ORCID
- GitHub
- Google
- Azure AD / Microsoft Entra ID
- Keycloak
- Any OAuth 2.0 / OIDC compliant provider

This plugin provides:
- OAuth 2.0 Authorization Code flow
- OpenID Connect support (where available)
- JWT token generation after successful authentication
- User auto-provisioning from OAuth2/OIDC claims
"""

__version__ = "0.1.0"

from .plugin import OAuth2TokenGeneratorPlugin
from .blueprint import oauth2_bp

__all__ = ["OAuth2TokenGeneratorPlugin", "oauth2_bp", "__version__"]
