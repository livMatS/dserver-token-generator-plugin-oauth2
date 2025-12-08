# dserver-token-generator-plugin-oauth2

A generic OAuth 2.0 / OpenID Connect token generator plugin for dserver that provides Single Sign-On (SSO) authentication with any OAuth2/OIDC compliant Identity Provider.

## Features

- **OAuth 2.0 Authorization Code flow** with PKCE support
- **OpenID Connect** support for providers that offer it
- **JWT token generation** after successful authentication
- **User auto-provisioning** from OAuth2/OIDC claims
- **Flexible attribute mapping** to adapt to any provider's response format
- **Built-in presets** for popular providers

## Installation

```bash
pip install dserver-token-generator-plugin-oauth2
```

Or for development:

```bash
pip install -e .
```

## Quick Start

1. Choose your OAuth2 provider and register an application to get client credentials
2. Configure the environment variables (see Configuration below)
3. Restart dserver
4. Users can authenticate at `/auth/login`

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `OAUTH2_AUTHORIZATION_URL` | Provider's authorization endpoint |
| `OAUTH2_TOKEN_URL` | Provider's token endpoint |
| `OAUTH2_CLIENT_ID` | Your application's client ID |
| `OAUTH2_CLIENT_SECRET` | Your application's client secret |

**Security Note**: For credentials (`OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET`), use a `.env` file instead of hardcoding them in `docker-compose.yml`:

```bash
# Copy the template
cp .env.template .env

# Edit with your credentials
nano .env
```

The `docker-compose.yml` uses variable substitution to read these values:
```yaml
OAUTH2_CLIENT_ID: "${OAUTH2_CLIENT_ID:-}"
OAUTH2_CLIENT_SECRET: "${OAUTH2_CLIENT_SECRET:-}"
```

### Optional Environment Variables

#### Provider Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_PROVIDER_NAME` | Identifier for the provider | `oauth2` |
| `OAUTH2_BASE_URL` | Base URL of your dserver instance | `http://localhost:5000` |
| `OAUTH2_USERINFO_URL` | OIDC userinfo endpoint | (none) |
| `OAUTH2_SCOPE` | OAuth2 scopes to request | `openid` |
| `OAUTH2_REDIRECT_URI` | Callback URL | `{OAUTH2_BASE_URL}/auth/callback` |

#### Attribute Mapping

The plugin needs to know how to extract user information from the OAuth2 provider's response. Different providers return user data in different formats.

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_ATTRIBUTE_MAP` | Maps provider fields to internal fields | `sub:user_id,email:email,name:display_name` |
| `OAUTH2_USERNAME_FIELD` | Which internal field to use as username | `user_id` |

**Format**: `provider_field:internal_field,provider_field2:internal_field2`

**Internal fields**:
- `user_id` - Unique identifier from the provider
- `username` - Username (if different from user_id)
- `email` - Email address
- `display_name` - Full display name
- `given_name` - First name
- `surname` - Last name

#### JWT Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_PRIVATE_KEY_FILE` | Path to RSA private key | `/app/jwt/jwt_key` |
| `JWT_PUBLIC_KEY_FILE` | Path to RSA public key | `/app/jwt/jwt_key.pub` |
| `JWT_ALGORITHM` | Signing algorithm | `RS256` |
| `JWT_ISSUER` | Token issuer claim | `dserver` |
| `JWT_AUDIENCE` | Token audience claim | `dserver` |
| `JWT_TOKEN_EXPIRY_HOURS` | Token validity period | `24` |

#### User Provisioning

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_AUTO_PROVISION_USERS` | Create users on first login | `true` |
| `OAUTH2_DEFAULT_USER_PERMISSIONS` | Permissions for new users | `search,retrieve` |

#### Redirect URLs

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH2_FRONTEND_URL` | Frontend base URL | `/` |
| `OAUTH2_LOGIN_SUCCESS_REDIRECT` | Redirect after successful login | `/` |
| `OAUTH2_LOGIN_ERROR_REDIRECT` | Redirect after failed login | `/login?error=auth_failed` |

## API Endpoints

All endpoints are under the `/auth` prefix.

### Authentication Flow

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | GET | Initiates OAuth2 flow, redirects to provider |
| `/auth/callback` | GET | Receives authorization code, exchanges for token |
| `/auth/logout` | GET | Clears session and token cookie |

### Token Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token` | GET | Returns current user's JWT token |
| `/auth/token` | POST | Exchange API key for token (programmatic access) |
| `/auth/refresh` | POST | Refresh an existing JWT token |
| `/auth/verify` | POST | Verify a token and return its claims |

### Information

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/info` | GET | Returns configured provider information |

### Response Examples

**GET /auth/token** (authenticated user):
```json
{
  "token": "eyJhbGciOiJSUzI1NiIs...",
  "username": "user@example.com",
  "provider": "oauth2",
  "token_type": "Bearer"
}
```

**GET /auth/info**:
```json
{
  "provider": "orcid",
  "login_url": "http://localhost:5000/auth/login",
  "configured": true
}
```

## CLI Commands

The plugin provides Flask CLI commands for management and debugging:

```bash
# Display current configuration
flask oauth2 show-config

# List available provider presets
flask oauth2 list-presets

# Show environment variables for a specific preset
flask oauth2 show-preset <provider>

# Validate the current configuration
flask oauth2 validate-config

# Test connectivity to the OAuth2 provider
flask oauth2 test-connection

# Generate a test JWT token
flask oauth2 test-jwt --username test@example.com
```

## How It Works

The plugin implements the standard OAuth 2.0 Authorization Code flow:

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  User    │     │  dserver │     │ OAuth2   │     │ Frontend │
│ Browser  │     │  Plugin  │     │ Provider │     │  App     │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ 1. Click Login │                │                │
     │───────────────>│                │                │
     │                │                │                │
     │ 2. Redirect to Provider         │                │
     │<───────────────│                │                │
     │                │                │                │
     │ 3. Authenticate│                │                │
     │────────────────────────────────>│                │
     │                │                │                │
     │ 4. Authorization Code           │                │
     │<────────────────────────────────│                │
     │                │                │                │
     │ 5. Code to Plugin               │                │
     │───────────────>│                │                │
     │                │                │                │
     │                │ 6. Exchange Code for Token      │
     │                │───────────────>│                │
     │                │                │                │
     │                │ 7. Access Token + User Info     │
     │                │<───────────────│                │
     │                │                │                │
     │                │ 8. Generate JWT│                │
     │                │────────┐       │                │
     │                │        │       │                │
     │                │<───────┘       │                │
     │                │                │                │
     │ 9. Redirect with JWT Cookie     │                │
     │<───────────────│                │                │
     │                │                │                │
     │ 10. Access Frontend             │                │
     │─────────────────────────────────────────────────>│
     │                │                │                │
```

## Provider-Specific Documentation

See the `provider-docs/` directory for detailed setup guides:

- **[ORCID](provider-docs/orcid.md)** - Researcher identification (recommended for academic use)

## Security Considerations

1. **Always use HTTPS in production** - OAuth2 tokens are transmitted in URLs and headers
2. **Keep client secrets secure** - Never commit secrets to version control
3. **Validate redirect URIs** - Ensure they match exactly in provider configuration
4. **Use state parameter** - The plugin automatically handles CSRF protection via OAuth2 state
5. **Protect JWT keys** - Restrict file permissions on private key files

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=dserver_token_generator_plugin_oauth2
```

### Adding a New Provider Preset

Edit `config.py` and add to the `PROVIDER_PRESETS` dictionary:

```python
PROVIDER_PRESETS = {
    "your_provider": {
        "name": "your_provider",
        "authorization_url": "https://provider.com/oauth/authorize",
        "token_url": "https://provider.com/oauth/token",
        "userinfo_url": "https://provider.com/userinfo",  # if applicable
        "scope": "openid email profile",
        "attribute_map": {
            "sub": "user_id",
            "email": "email",
            "name": "display_name",
        },
        "username_field": "email",
    },
}
```

## License

MIT License
