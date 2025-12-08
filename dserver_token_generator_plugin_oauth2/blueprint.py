"""
Flask blueprint for OAuth2 authentication.

This blueprint provides the following endpoints:
- GET /auth/login - Initiate OAuth2 authorization flow
- GET /auth/callback - OAuth2 callback (receives authorization code)
- GET /auth/logout - Clear session and logout
- GET /auth/token - Get current user's JWT token
- POST /auth/token - Exchange credentials for JWT token (API access)
- POST /auth/refresh - Refresh an existing JWT token
- POST /auth/verify - Verify a JWT token
"""

import logging
import secrets
from typing import Optional

import httpx
from authlib.integrations.requests_client import OAuth2Session
from flask import (
    jsonify,
    make_response,
    redirect,
    request,
    session,
    url_for,
)
from flask_smorest import Blueprint

from .config import PluginConfig
from .jwt_utils import JwtTokenGenerator
from .user_provisioning import UserProvisioner

logger = logging.getLogger(__name__)

# Create the blueprint using flask_smorest Blueprint (required by dservercore)
oauth2_bp = Blueprint(
    "oauth2_auth",
    __name__,
    url_prefix="/auth",
    description="OAuth2 authentication endpoints"
)

# Plugin configuration (initialized on first request)
_config: PluginConfig = None
_jwt_generator: JwtTokenGenerator = None
_user_provisioner: UserProvisioner = None


def get_config() -> PluginConfig:
    """Get or initialize plugin configuration."""
    global _config
    if _config is None:
        _config = PluginConfig.from_env()
    return _config


def get_jwt_generator() -> JwtTokenGenerator:
    """Get or initialize JWT token generator."""
    global _jwt_generator
    if _jwt_generator is None:
        config = get_config()
        _jwt_generator = JwtTokenGenerator(config.jwt)
    return _jwt_generator


def get_user_provisioner() -> UserProvisioner:
    """Get or initialize user provisioner."""
    global _user_provisioner
    if _user_provisioner is None:
        config = get_config()
        _user_provisioner = UserProvisioner(
            auto_provision=config.auto_provision_users,
            default_permissions=config.default_user_permissions,
        )
    return _user_provisioner


def create_oauth2_session() -> OAuth2Session:
    """Create an OAuth2 session for the configured provider."""
    config = get_config()
    return OAuth2Session(
        client_id=config.oauth2.client_id,
        client_secret=config.oauth2.client_secret,
        redirect_uri=config.oauth2.redirect_uri,
        scope=config.oauth2.scope,
    )


def extract_user_info(token_response: dict, userinfo: Optional[dict] = None) -> dict:
    """
    Extract user information from OAuth2 token response and/or userinfo.

    Some providers (like ORCID) return user info directly in the token response,
    while others require a separate userinfo endpoint call.

    Args:
        token_response: The OAuth2 token response
        userinfo: Optional userinfo response from userinfo endpoint

    Returns:
        Dictionary with extracted user information
    """
    config = get_config()

    # Combine token response and userinfo
    data = {**token_response}
    if userinfo:
        data.update(userinfo)

    # Map attributes according to configuration
    user_data = {}
    for provider_field, internal_field in config.oauth2.attribute_map.items():
        if provider_field in data:
            user_data[internal_field] = data[provider_field]

    # Store the raw provider user ID
    if "sub" in data:
        user_data["provider_user_id"] = data["sub"]
    elif "id" in data:
        user_data["provider_user_id"] = str(data["id"])
    elif "orcid" in data:
        user_data["provider_user_id"] = data["orcid"]

    return user_data


def get_username_from_user_data(user_data: dict) -> Optional[str]:
    """
    Determine the username from extracted user data.

    Args:
        user_data: Mapped user attributes

    Returns:
        Username string or None
    """
    config = get_config()
    username_field = config.oauth2.username_field

    if username_field in user_data:
        return str(user_data[username_field])

    # Fallbacks
    for field in ["user_id", "email", "username", "provider_user_id"]:
        if field in user_data:
            return str(user_data[field])

    return None


@oauth2_bp.route("/login")
def login():
    """
    Initiate OAuth2 authorization flow.

    This endpoint redirects the user to the OAuth2 provider for authentication.

    Query Parameters:
        next: URL to redirect to after successful login (optional)
    """
    try:
        config = get_config()

        if not config.oauth2.authorization_url:
            return jsonify({
                "error": "OAuth2 not configured",
                "message": "OAUTH2_AUTHORIZATION_URL is not set"
            }), 500

        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        session["oauth2_state"] = state
        session.modified = True  # Ensure session is saved

        # Store the return URL
        next_url = request.args.get("next", config.login_success_redirect)
        session["auth_return_url"] = next_url

        logger.debug(f"Login: Generated state={state[:16]}..., session keys={list(session.keys())}")

        # Build authorization URL
        oauth = create_oauth2_session()
        authorization_url, _ = oauth.create_authorization_url(
            config.oauth2.authorization_url,
            state=state,
        )

        logger.info(f"Initiating OAuth2 login, redirecting to provider")
        logger.debug(f"Authorization URL: {authorization_url}")
        return redirect(authorization_url)

    except Exception as e:
        logger.error(f"Error initiating OAuth2 login: {e}")
        return jsonify({"error": "Failed to initiate authentication"}), 500


@oauth2_bp.route("/callback")
def callback():
    """
    OAuth2 callback endpoint.

    This endpoint receives the authorization code from the OAuth2 provider
    and exchanges it for an access token.
    """
    try:
        config = get_config()

        # Verify state for CSRF protection
        state = request.args.get("state")
        stored_state = session.pop("oauth2_state", None)

        logger.debug(f"Callback: Received state={state[:16] if state else 'None'}..., "
                    f"stored_state={stored_state[:16] if stored_state else 'None'}..., "
                    f"session keys={list(session.keys())}")

        if not state or state != stored_state:
            logger.warning(f"OAuth2 state mismatch - state={state}, stored_state={stored_state}")
            logger.warning(f"Session contents: {dict(session)}")
            return redirect(config.login_error_redirect)

        # Check for errors from provider
        error = request.args.get("error")
        if error:
            error_description = request.args.get("error_description", "Unknown error")
            logger.error(f"OAuth2 error: {error} - {error_description}")
            return redirect(config.login_error_redirect)

        # Get authorization code
        code = request.args.get("code")
        if not code:
            logger.error("No authorization code received")
            return redirect(config.login_error_redirect)

        # Exchange code for token
        oauth = create_oauth2_session()
        token_response = oauth.fetch_token(
            config.oauth2.token_url,
            authorization_response=request.url,
            code=code,
        )

        logger.debug(f"Token response: {token_response}")

        # Fetch userinfo if endpoint is configured
        userinfo = None
        if config.oauth2.userinfo_url:
            try:
                access_token = token_response.get("access_token")
                with httpx.Client() as client:
                    resp = client.get(
                        config.oauth2.userinfo_url,
                        headers={"Authorization": f"Bearer {access_token}"}
                    )
                    resp.raise_for_status()
                    userinfo = resp.json()
                    logger.debug(f"Userinfo response: {userinfo}")
            except Exception as e:
                logger.warning(f"Failed to fetch userinfo: {e}")

        # Extract user information
        user_data = extract_user_info(token_response, userinfo)
        logger.debug(f"Extracted user data: {user_data}")

        # Get username
        username = get_username_from_user_data(user_data)
        if not username:
            logger.error("Could not determine username from OAuth2 response")
            return redirect(config.login_error_redirect)

        # Provision user
        provisioner = get_user_provisioner()
        user_info = provisioner.provision_user(
            username=username,
            email=user_data.get("email"),
            display_name=user_data.get("display_name"),
            given_name=user_data.get("given_name"),
            surname=user_data.get("surname"),
            provider=config.oauth2.name,
            provider_user_id=user_data.get("provider_user_id"),
        )

        # Generate JWT token
        jwt_gen = get_jwt_generator()
        token = jwt_gen.generate_token(
            username=user_info["username"],
            email=user_info.get("email"),
            display_name=user_info.get("display_name"),
            permissions=user_info.get("permissions"),
            additional_claims={
                "provider": config.oauth2.name,
                "provider_user_id": user_data.get("provider_user_id"),
            },
        )

        # Store session info
        session["username"] = username
        session["jwt_token"] = token
        session["provider"] = config.oauth2.name

        # Redirect to frontend with token
        return_url = session.pop("auth_return_url", config.login_success_redirect)

        # Append token as query parameter for cross-origin webapp
        # The webapp will read this and use it to authenticate
        separator = "&" if "?" in return_url else "?"
        redirect_url = f"{return_url}{separator}token={token}"

        response = make_response(redirect(redirect_url))

        # Also set cookie for same-origin access
        response.set_cookie(
            "dserver_token",
            token,
            httponly=False,  # Allow JavaScript access
            secure=request.is_secure,
            samesite="Lax",
            max_age=config.jwt.token_expiry_hours * 3600,
        )

        logger.info(f"User {username} authenticated successfully via {config.oauth2.name}")
        return response

    except Exception as e:
        logger.exception(f"Error processing OAuth2 callback: {e}")
        return redirect(get_config().login_error_redirect)


@oauth2_bp.route("/logout")
def logout():
    """
    Logout and clear session.
    """
    config = get_config()

    # Clear session
    session.clear()

    # Clear token cookie
    response = make_response(redirect(config.frontend_url))
    response.delete_cookie("dserver_token")

    logger.info("User logged out")
    return response


@oauth2_bp.route("/token", methods=["GET"])
def get_token():
    """
    Get the current user's JWT token.

    Returns:
        JSON with token or error
    """
    token = session.get("jwt_token")

    if not token:
        return jsonify({
            "error": "Not authenticated",
            "login_url": url_for("oauth2_auth.login", _external=True),
        }), 401

    username = session.get("username")
    provider = session.get("provider")

    return jsonify({
        "token": token,
        "username": username,
        "provider": provider,
        "token_type": "Bearer",
    })


@oauth2_bp.route("/token", methods=["POST"])
def create_token():
    """
    Exchange credentials for a JWT token (API access).

    Request body:
        {
            "api_key": "...",
            "username": "..."
        }

    Returns:
        JSON with token or error
    """
    import os

    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing request body"}), 400

    api_key = data.get("api_key")
    username = data.get("username")

    if not api_key or not username:
        return jsonify({"error": "Missing api_key or username"}), 400

    # Validate API key
    valid_api_key = os.environ.get("OAUTH2_API_KEY")

    if not valid_api_key:
        logger.warning("API key authentication not configured")
        return jsonify({"error": "API authentication not configured"}), 501

    if api_key != valid_api_key:
        logger.warning(f"Invalid API key for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate token
    jwt_gen = get_jwt_generator()
    token = jwt_gen.generate_token(
        username=username,
        permissions=["search", "retrieve"],
    )

    return jsonify({
        "token": token,
        "username": username,
        "token_type": "Bearer",
    })


@oauth2_bp.route("/refresh", methods=["POST"])
def refresh_token():
    """
    Refresh an existing JWT token.

    Request body:
        {
            "token": "existing_jwt_token"
        }

    Returns:
        JSON with new token or error
    """
    data = request.get_json()

    if not data or "token" not in data:
        return jsonify({"error": "Missing token"}), 400

    jwt_gen = get_jwt_generator()
    new_token = jwt_gen.refresh_token(data["token"])

    if not new_token:
        return jsonify({"error": "Invalid or expired token"}), 401

    return jsonify({
        "token": new_token,
        "token_type": "Bearer",
    })


@oauth2_bp.route("/verify", methods=["POST"])
def verify_token():
    """
    Verify a JWT token and return its claims.

    Request body:
        {
            "token": "jwt_token_to_verify"
        }

    Returns:
        JSON with token claims or error
    """
    data = request.get_json()

    if not data or "token" not in data:
        return jsonify({"error": "Missing token"}), 400

    jwt_gen = get_jwt_generator()
    claims = jwt_gen.verify_token(data["token"])

    if not claims:
        return jsonify({"error": "Invalid or expired token"}), 401

    return jsonify({
        "valid": True,
        "claims": claims,
    })


@oauth2_bp.route("/info")
def auth_info():
    """
    Return information about the configured OAuth2 provider.

    This endpoint can be used by the frontend to display login options.
    """
    config = get_config()

    return jsonify({
        "provider": config.oauth2.name,
        "login_url": url_for("oauth2_auth.login", _external=True),
        "configured": bool(config.oauth2.authorization_url and config.oauth2.client_id),
    })
