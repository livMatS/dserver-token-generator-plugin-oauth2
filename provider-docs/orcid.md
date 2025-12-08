# ORCID Provider Setup

This guide explains how to configure the OAuth2 plugin to authenticate users via ORCID (Open Researcher and Contributor ID).

## What is ORCID?

ORCID provides persistent digital identifiers (ORCID iDs) for researchers. An ORCID iD looks like `0000-0001-2345-6789` and uniquely identifies a researcher across the scholarly ecosystem.

Using ORCID for authentication is ideal for:
- Academic and research data repositories
- Scientific collaboration platforms
- Research data management systems

## Prerequisites

- An ORCID account (free at https://orcid.org/register)
- Your dserver instance URL (for redirect URI configuration)

## Setup Steps

### 1. Create an ORCID Developer Account

#### For Testing (Sandbox)

1. Create a sandbox account at https://sandbox.orcid.org/register
2. Go to https://sandbox.orcid.org/developer-tools
3. Register your application

#### For Production

1. Go to https://orcid.org/developer-tools
2. Sign in with your ORCID account
3. Click "Register for the free ORCID public API"

### 2. Register Your Application

Fill in the application details:

| Field | Example Value |
|-------|---------------|
| Application Name | My dserver Instance |
| Application URL | https://dserver.example.com |
| Description | Dataset repository using dserver |

**Important**: Add the redirect URI:
- Production: `https://your-dserver.example.com/auth/callback`
- Development: `http://localhost:5000/auth/callback`

After saving, you'll receive:
- **Client ID**: `APP-XXXXXXXXXXXX`
- **Client Secret**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### 3. Configure the Plugin

Add these environment variables to your `docker-compose.yml`:

```yaml
environment:
  # Provider identification
  OAUTH2_PROVIDER_NAME: "orcid"
  OAUTH2_BASE_URL: "https://your-dserver.example.com"  # or http://localhost:5000 for dev

  # ORCID endpoints
  # For Production:
  OAUTH2_AUTHORIZATION_URL: "https://orcid.org/oauth/authorize"
  OAUTH2_TOKEN_URL: "https://orcid.org/oauth/token"

  # For Sandbox (testing):
  # OAUTH2_AUTHORIZATION_URL: "https://sandbox.orcid.org/oauth/authorize"
  # OAUTH2_TOKEN_URL: "https://sandbox.orcid.org/oauth/token"

  # Your credentials from ORCID developer tools
  OAUTH2_CLIENT_ID: "APP-XXXXXXXXXXXX"
  OAUTH2_CLIENT_SECRET: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

  # ORCID-specific settings
  OAUTH2_SCOPE: "/authenticate"
  OAUTH2_ATTRIBUTE_MAP: "orcid:user_id,name:display_name"
  OAUTH2_USERNAME_FIELD: "user_id"

  # Do NOT set OAUTH2_USERINFO_URL - ORCID returns user info in the token response

  # User provisioning
  OAUTH2_AUTO_PROVISION_USERS: "true"
  OAUTH2_DEFAULT_USER_PERMISSIONS: "search,retrieve"

  # Redirect URLs
  OAUTH2_LOGIN_SUCCESS_REDIRECT: "https://your-webapp.example.com"
  OAUTH2_LOGIN_ERROR_REDIRECT: "https://your-webapp.example.com/login?error=auth_failed"
```

### 4. Verify Configuration

```bash
# Check configuration
docker compose exec dserver flask oauth2 show-config

# Validate settings
docker compose exec dserver flask oauth2 validate-config

# Test connectivity to ORCID
docker compose exec dserver flask oauth2 test-connection
```

### 5. Test the Login Flow

1. Navigate to `http://localhost:5000/auth/login`
2. You should be redirected to ORCID's login page
3. Sign in with your ORCID credentials
4. Grant permission to the application
5. You should be redirected back with a valid session

## How ORCID OAuth2 Works

ORCID uses a slightly non-standard OAuth2 flow. Unlike most providers, ORCID returns user information directly in the token response instead of requiring a separate userinfo endpoint call.

### Token Response

When the plugin exchanges the authorization code for a token, ORCID returns:

```json
{
  "access_token": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "token_type": "bearer",
  "refresh_token": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "expires_in": 631138518,
  "scope": "/authenticate",
  "name": "John Smith",
  "orcid": "0000-0001-2345-6789"
}
```

The plugin extracts:
- `orcid` → Used as the username (e.g., `0000-0001-2345-6789`)
- `name` → Used as the display name (e.g., `John Smith`)

### Username Format

Users authenticated via ORCID will have usernames in ORCID iD format:

```
0000-0001-2345-6789
```

This is a globally unique, persistent identifier.

## ORCID Scopes

| Scope | Description | Use Case |
|-------|-------------|----------|
| `/authenticate` | Verify identity only | **Recommended for dserver** |
| `/read-limited` | Read limited-access data | If you need profile details |
| `/activities/update` | Update works, education, etc. | Not needed for auth |
| `/person/update` | Update personal info | Not needed for auth |

For dserver, `/authenticate` is sufficient - we only need to verify the user's identity.

## Sandbox vs Production

| Feature | Sandbox | Production |
|---------|---------|------------|
| URL | sandbox.orcid.org | orcid.org |
| Real users | No (test accounts only) | Yes |
| Rate limits | Lower | Higher |
| Use for | Development & testing | Live deployments |

**Important**: Sandbox ORCID iDs are not real. Create test accounts at https://sandbox.orcid.org/register for development.

## Troubleshooting

### "Invalid redirect_uri"

The redirect URI in your ORCID developer settings must exactly match `{OAUTH2_BASE_URL}/auth/callback`.

Common issues:
- HTTP vs HTTPS mismatch
- Missing or extra trailing slash
- Wrong port number

### "Invalid client_id or client_secret"

- Double-check credentials are copied correctly
- Ensure you're using the right environment (sandbox vs production)
- Verify the application is still active in ORCID developer tools

### "No user info returned"

Make sure:
- `OAUTH2_USERINFO_URL` is NOT set (ORCID doesn't use a separate userinfo endpoint)
- `OAUTH2_ATTRIBUTE_MAP` includes `orcid:user_id,name:display_name`

### User appears with empty display name

Some ORCID users have visibility settings that hide their name. The `name` field may be empty for these users. The ORCID iD will still be available as the username.

## Production Checklist

Before going live:

- [ ] Register application at orcid.org (not sandbox)
- [ ] Use HTTPS for all URLs
- [ ] Configure correct redirect URI in ORCID developer tools
- [ ] Store client secret securely (not in version control)
- [ ] Test complete login flow
- [ ] Verify JWT tokens are generated correctly
- [ ] Test with multiple ORCID accounts

## Additional Resources

- [ORCID Developer Tools](https://orcid.org/developer-tools)
- [ORCID API Documentation](https://info.orcid.org/documentation/)
- [ORCID OAuth Tutorial](https://info.orcid.org/documentation/api-tutorials/api-tutorial-get-and-authenticated-orcid-id/)
- [ORCID Sandbox](https://sandbox.orcid.org)
- [ORCID Member API vs Public API](https://info.orcid.org/documentation/features/public-api/)
