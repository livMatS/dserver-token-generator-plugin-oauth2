"""Tests for OAuth2 user provisioning."""

import sys
import pytest
from unittest.mock import patch, MagicMock
from dserver_token_generator_plugin_oauth2.user_provisioning import UserProvisioner


class TestUserProvisioner:
    def test_provision_user_basic(self):
        provisioner = UserProvisioner()
        result = provisioner.provision_user(
            username="testuser",
            email="test@example.com",
            provider="orcid",
        )
        assert result["username"] == "testuser"
        assert result["email"] == "test@example.com"
        assert result["provider"] == "orcid"

    def test_provision_user_returns_dict(self):
        provisioner = UserProvisioner()
        result = provisioner.provision_user(username="user1")
        assert isinstance(result, dict)
        assert "username" in result

    def test_display_name_from_given_and_surname(self):
        provisioner = UserProvisioner()
        result = provisioner.provision_user(
            username="jsmith",
            given_name="John",
            surname="Smith",
        )
        assert result["display_name"] == "John Smith"

    def test_display_name_given_name_only(self):
        provisioner = UserProvisioner()
        result = provisioner.provision_user(
            username="jsmith",
            given_name="John",
        )
        assert result["display_name"] == "John"

    def test_display_name_surname_only(self):
        provisioner = UserProvisioner()
        result = provisioner.provision_user(
            username="jsmith",
            surname="Smith",
        )
        assert result["display_name"] == "Smith"

    def test_explicit_display_name_preserved(self):
        """Explicit display_name takes priority over given_name + surname construction."""
        provisioner = UserProvisioner()
        result = provisioner.provision_user(
            username="jsmith",
            display_name="Dr. Smith",
            given_name="John",
            surname="Smith",
        )
        assert result["display_name"] == "Dr. Smith"

    def test_provider_user_id_in_result(self):
        provisioner = UserProvisioner()
        result = provisioner.provision_user(
            username="0000-0001-2345-6789",
            provider="orcid",
            provider_user_id="0000-0001-2345-6789",
        )
        assert result["provider_user_id"] == "0000-0001-2345-6789"

    def test_no_db_error_propagation(self):
        """provision_user must not raise even if dservercore DB update fails."""
        provisioner = UserProvisioner()
        # Simulate dservercore import failure
        with patch.dict(sys.modules, {
            "dservercore": None,
            "dservercore.sql_models": None,
        }):
            result = provisioner.provision_user(
                username="testuser",
                display_name="Test User",
            )
        assert result["username"] == "testuser"

    def test_auto_provision_flag_ignored(self):
        """auto_provision parameter is accepted but has no effect."""
        provisioner = UserProvisioner(auto_provision=True)
        result = provisioner.provision_user(username="u1")
        assert result["username"] == "u1"
