"""
Flask CLI commands for OAuth2 plugin management.

These commands help with setup, debugging, and maintenance of the
OAuth2 integration.
"""

import click
from flask import current_app
from flask.cli import with_appcontext

from .config import PluginConfig, PROVIDER_PRESETS


@click.group("oauth2")
def oauth2_cli():
    """OAuth2 token generator management commands."""
    pass


@oauth2_cli.command("show-config")
@with_appcontext
def show_config():
    """Display current OAuth2 configuration."""
    config = PluginConfig.from_env()

    click.echo("=== OAuth2 Provider Configuration ===")
    click.echo(f"Provider Name: {config.oauth2.name}")
    click.echo(f"Authorization URL: {config.oauth2.authorization_url or 'Not configured'}")
    click.echo(f"Token URL: {config.oauth2.token_url or 'Not configured'}")
    click.echo(f"Userinfo URL: {config.oauth2.userinfo_url or 'Not configured'}")
    click.echo(f"Redirect URI: {config.oauth2.redirect_uri}")
    click.echo(f"Scope: {config.oauth2.scope}")
    click.echo(f"Client ID: {config.oauth2.client_id[:8] + '...' if config.oauth2.client_id else 'Not configured'}")
    click.echo(f"Client Secret: {'Configured' if config.oauth2.client_secret else 'Not configured'}")

    click.echo("\n=== Attribute Mapping ===")
    for provider_field, internal_field in config.oauth2.attribute_map.items():
        click.echo(f"  {provider_field} -> {internal_field}")
    click.echo(f"Username field: {config.oauth2.username_field}")

    click.echo("\n=== JWT Configuration ===")
    click.echo(f"Private Key File: {config.jwt.private_key_file}")
    click.echo(f"Public Key File: {config.jwt.public_key_file}")
    click.echo(f"Algorithm: {config.jwt.algorithm}")
    click.echo(f"Issuer: {config.jwt.issuer}")
    click.echo(f"Token Expiry: {config.jwt.token_expiry_hours} hours")

    click.echo("\n=== User Provisioning ===")
    click.echo(f"Auto Provision: {config.auto_provision_users}")
    click.echo(f"Default Permissions: {config.default_user_permissions}")


@oauth2_cli.command("list-presets")
def list_presets():
    """List available provider presets."""
    click.echo("=== Available Provider Presets ===\n")

    for name, preset in PROVIDER_PRESETS.items():
        click.echo(f"{name}:")
        click.echo(f"  Authorization URL: {preset['authorization_url']}")
        click.echo(f"  Token URL: {preset['token_url']}")
        click.echo(f"  Userinfo URL: {preset.get('userinfo_url') or 'N/A'}")
        click.echo(f"  Scope: {preset['scope']}")
        click.echo()


@oauth2_cli.command("show-preset")
@click.argument("name")
def show_preset(name):
    """Show environment variables for a provider preset."""
    preset = PROVIDER_PRESETS.get(name.lower())

    if not preset:
        click.echo(f"Unknown preset: {name}", err=True)
        click.echo(f"Available presets: {', '.join(PROVIDER_PRESETS.keys())}")
        return

    click.echo(f"=== Environment Variables for {name} ===\n")
    click.echo("# Copy these to your docker-compose.yml or .env file\n")

    click.echo(f'OAUTH2_PROVIDER_NAME: "{preset["name"]}"')
    click.echo(f'OAUTH2_AUTHORIZATION_URL: "{preset["authorization_url"]}"')
    click.echo(f'OAUTH2_TOKEN_URL: "{preset["token_url"]}"')
    if preset.get("userinfo_url"):
        click.echo(f'OAUTH2_USERINFO_URL: "{preset["userinfo_url"]}"')
    click.echo(f'OAUTH2_SCOPE: "{preset["scope"]}"')

    # Format attribute map
    attr_map = ",".join(f"{k}:{v}" for k, v in preset["attribute_map"].items())
    click.echo(f'OAUTH2_ATTRIBUTE_MAP: "{attr_map}"')
    click.echo(f'OAUTH2_USERNAME_FIELD: "{preset["username_field"]}"')

    click.echo("\n# You must also set:")
    click.echo("OAUTH2_CLIENT_ID: <your-client-id>")
    click.echo("OAUTH2_CLIENT_SECRET: <your-client-secret>")


@oauth2_cli.command("test-jwt")
@click.option("--username", default="test@example.com", help="Test username")
@with_appcontext
def test_jwt(username):
    """Generate a test JWT token."""
    from .jwt_utils import JwtTokenGenerator
    from .config import JwtConfig

    try:
        jwt_config = JwtConfig.from_env()
        generator = JwtTokenGenerator(jwt_config)

        token = generator.generate_token(
            username=username,
            email=f"{username}",
            display_name="Test User",
            permissions=["search", "retrieve"],
        )

        click.echo("=== Generated JWT Token ===")
        click.echo(token)
        click.echo("\n=== Token Verification ===")

        claims = generator.verify_token(token)
        if claims:
            click.echo("Token is valid!")
            for key, value in claims.items():
                click.echo(f"  {key}: {value}")
        else:
            click.echo("Token verification failed!", err=True)

    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Make sure JWT key files are configured correctly.")


@oauth2_cli.command("validate-config")
@with_appcontext
def validate_config():
    """Validate the current configuration."""
    from pathlib import Path

    config = PluginConfig.from_env()
    errors = []
    warnings = []

    # Check JWT files
    if not Path(config.jwt.private_key_file).exists():
        errors.append(f"JWT private key not found: {config.jwt.private_key_file}")
    if not Path(config.jwt.public_key_file).exists():
        errors.append(f"JWT public key not found: {config.jwt.public_key_file}")

    # Check OAuth2 configuration
    if not config.oauth2.authorization_url:
        errors.append("OAUTH2_AUTHORIZATION_URL not configured")
    if not config.oauth2.token_url:
        errors.append("OAUTH2_TOKEN_URL not configured")
    if not config.oauth2.client_id:
        errors.append("OAUTH2_CLIENT_ID not configured")
    if not config.oauth2.client_secret:
        errors.append("OAUTH2_CLIENT_SECRET not configured")

    if not config.oauth2.userinfo_url:
        warnings.append("OAUTH2_USERINFO_URL not configured (may be OK for some providers)")

    # Output results
    if warnings:
        click.echo("=== Warnings ===")
        for warning in warnings:
            click.echo(f"  ! {warning}")

    if errors:
        click.echo("\n=== Errors ===")
        for error in errors:
            click.echo(f"  x {error}")
        click.echo(f"\nConfiguration validation failed with {len(errors)} error(s)")
        return

    click.echo("\n[OK] Configuration is valid!")


@oauth2_cli.command("test-connection")
@with_appcontext
def test_connection():
    """Test connectivity to the OAuth2 provider."""
    import httpx

    config = PluginConfig.from_env()

    click.echo("=== Testing OAuth2 Provider Connectivity ===\n")

    # Test authorization URL
    if config.oauth2.authorization_url:
        try:
            with httpx.Client() as client:
                resp = client.head(config.oauth2.authorization_url, follow_redirects=True, timeout=10)
                click.echo(f"[OK] Authorization URL reachable: {config.oauth2.authorization_url}")
        except Exception as e:
            click.echo(f"[FAIL] Authorization URL: {e}")
    else:
        click.echo("[SKIP] Authorization URL not configured")

    # Test token URL
    if config.oauth2.token_url:
        try:
            with httpx.Client() as client:
                # Just check if the endpoint exists (will return error without credentials)
                resp = client.post(config.oauth2.token_url, timeout=10)
                click.echo(f"[OK] Token URL reachable: {config.oauth2.token_url}")
        except httpx.HTTPStatusError:
            # Expected - we're not sending valid credentials
            click.echo(f"[OK] Token URL reachable: {config.oauth2.token_url}")
        except Exception as e:
            click.echo(f"[FAIL] Token URL: {e}")
    else:
        click.echo("[SKIP] Token URL not configured")

    # Test userinfo URL
    if config.oauth2.userinfo_url:
        try:
            with httpx.Client() as client:
                resp = client.get(config.oauth2.userinfo_url, timeout=10)
                click.echo(f"[OK] Userinfo URL reachable: {config.oauth2.userinfo_url}")
        except httpx.HTTPStatusError:
            # Expected - we're not sending valid token
            click.echo(f"[OK] Userinfo URL reachable: {config.oauth2.userinfo_url}")
        except Exception as e:
            click.echo(f"[FAIL] Userinfo URL: {e}")
    else:
        click.echo("[SKIP] Userinfo URL not configured")
