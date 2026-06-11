"""Security tests for the OAuth2 login/callback flow.

These encode the fixes for the 2026-06 audit findings: open redirect via
?next=, JWT delivered as a query parameter, and a JS-readable token cookie.
"""

import pytest

import dserver_token_generator_plugin_oauth2.blueprint as bp_module

from .conftest import FRONTEND


class FakeOAuthSession:
    def fetch_token(self, url, **kwargs):
        return {"sub": "user1", "name": "User One"}


class FakeProvisioner:
    def provision_user(self, username, **kwargs):
        return {"username": username, "email": None,
                "display_name": None, "permissions": ["search"]}


class FakeJwtGenerator:
    def generate_token(self, username, **kwargs):
        return "FAKE.JWT.TOKEN"


@pytest.fixture
def authenticated_callback(monkeypatch, client):
    """Prime the session state and stub out provider/JWT interactions."""
    monkeypatch.setattr(
        bp_module, "create_oauth2_session", lambda: FakeOAuthSession())
    monkeypatch.setattr(bp_module, "_user_provisioner", FakeProvisioner())
    monkeypatch.setattr(bp_module, "_jwt_generator", FakeJwtGenerator())

    def call(state="good-state", query_state="good-state", next_url=None):
        with client.session_transaction() as session:
            session["oauth2_state"] = state
            if next_url is not None:
                session["auth_return_url"] = next_url
        return client.get(
            f"/auth/callback?state={query_state}&code=auth-code")

    return call


# --- Open redirect via ?next= -------------------------------------------

def test_login_rejects_foreign_origin_next(client):
    response = client.get("/auth/login?next=https://evil.example/steal")
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert "evil.example" not in session.get("auth_return_url", "")


def test_login_rejects_protocol_relative_next(client):
    response = client.get("/auth/login?next=//evil.example/steal")
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert "evil.example" not in session.get("auth_return_url", "")


def test_login_accepts_relative_next(client):
    response = client.get("/auth/login?next=/datasets/abc")
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["auth_return_url"] == "/datasets/abc"


def test_login_accepts_frontend_origin_next(client):
    response = client.get(f"/auth/login?next={FRONTEND}/datasets/abc")
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["auth_return_url"] == f"{FRONTEND}/datasets/abc"


def test_login_redirects_to_provider_with_state(client):
    response = client.get("/auth/login")
    assert response.status_code == 302
    assert response.location.startswith("https://provider.example/authorize")
    assert "state=" in response.location
    with client.session_transaction() as session:
        assert session["oauth2_state"]


# --- State (CSRF) validation ----------------------------------------------

def test_callback_rejects_wrong_state(client, authenticated_callback):
    response = authenticated_callback(
        state="good-state", query_state="attacker-state")
    assert response.status_code == 302
    assert "error=auth_failed" in response.location
    assert "FAKE.JWT.TOKEN" not in response.location


def test_callback_rejects_missing_state(client, authenticated_callback,
                                        monkeypatch):
    monkeypatch.setattr(
        bp_module, "create_oauth2_session", lambda: FakeOAuthSession())
    response = client.get("/auth/callback?code=auth-code")
    assert response.status_code == 302
    assert "error=auth_failed" in response.location


# --- Token delivery --------------------------------------------------------

def _token_cookie_headers(response):
    return [
        value for name, value in response.headers.items()
        if name.lower() == "set-cookie" and "dserver_token" in value
    ]


def test_callback_token_not_in_query_string(client, authenticated_callback):
    """The JWT must not ride in the query string (history, logs, Referer)."""
    response = authenticated_callback(next_url=f"{FRONTEND}/")
    assert response.status_code == 302
    query = response.location.split("#")[0]
    assert "token=" not in query


def test_callback_token_delivered_in_fragment(client, authenticated_callback):
    response = authenticated_callback(next_url=f"{FRONTEND}/")
    assert response.status_code == 302
    assert "#token=FAKE.JWT.TOKEN" in response.location


def test_callback_sets_no_token_cookie(client, authenticated_callback):
    """The JWT lives in the server-side session only; duplicating it into
    a cookie would create a second copy of the credential that nothing
    consumes (the webapp cannot read an HttpOnly cookie)."""
    response = authenticated_callback(next_url=f"{FRONTEND}/")
    assert not _token_cookie_headers(response)


def test_callback_session_only_mode_keeps_token_out_of_url(
        monkeypatch, client, authenticated_callback):
    """With OAUTH2_DELIVER_TOKEN_IN_FRAGMENT=false the token must not
    appear anywhere in the redirect URL (session-only, same-origin
    deployments); the webapp fetches it from GET /auth/token instead."""
    monkeypatch.setenv("OAUTH2_DELIVER_TOKEN_IN_FRAGMENT", "false")
    monkeypatch.setattr(bp_module, "_config", None)  # re-read env

    response = authenticated_callback(next_url=f"{FRONTEND}/")
    assert response.status_code == 302
    assert "FAKE.JWT.TOKEN" not in response.location
    assert "#" not in response.location
    assert not _token_cookie_headers(response)

    response = client.get("/auth/token")
    assert response.status_code == 200
    assert response.get_json()["token"] == "FAKE.JWT.TOKEN"


def test_token_endpoint_requires_session(client):
    response = client.get("/auth/token")
    assert response.status_code == 401


# --- Logout -----------------------------------------------------------------

def test_logout_redirects_browser_and_clears_session(
        client, authenticated_callback):
    authenticated_callback(next_url=f"{FRONTEND}/")
    response = client.get("/auth/logout")
    assert response.status_code == 302
    assert response.location.startswith(FRONTEND)
    assert client.get("/auth/token").status_code == 401


def test_logout_returns_json_for_xhr_and_clears_session(
        client, authenticated_callback):
    authenticated_callback(next_url=f"{FRONTEND}/")
    response = client.post(
        "/auth/logout", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.get_json() == {"success": True}
    assert client.get("/auth/token").status_code == 401
