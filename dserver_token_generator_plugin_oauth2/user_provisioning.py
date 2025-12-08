"""
User provisioning for OAuth2 authenticated users.

This module handles creating and updating user records in dserver
after successful OAuth2 authentication.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class UserProvisioner:
    """
    Handle user provisioning after OAuth2 authentication.

    This class manages the lifecycle of user accounts in dserver,
    including auto-provisioning new users and updating existing ones.
    """

    def __init__(
        self,
        auto_provision: bool = True,
        default_permissions: Optional[list] = None,
    ):
        """
        Initialize the user provisioner.

        Args:
            auto_provision: Whether to automatically create users on first login
            default_permissions: Default permissions for new users
        """
        self.auto_provision = auto_provision
        self.default_permissions = default_permissions or ["search", "retrieve"]

    def provision_user(
        self,
        username: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        given_name: Optional[str] = None,
        surname: Optional[str] = None,
        provider: Optional[str] = None,
        provider_user_id: Optional[str] = None,
    ) -> dict:
        """
        Provision a user account after OAuth2 authentication.

        Args:
            username: Unique username
            email: User's email address
            display_name: User's display name
            given_name: User's first name
            surname: User's last name
            provider: OAuth2 provider name (e.g., "orcid", "github")
            provider_user_id: User ID from the OAuth2 provider

        Returns:
            Dictionary with user info and permissions
        """
        # Build display name if not provided
        if not display_name and (given_name or surname):
            parts = [p for p in [given_name, surname] if p]
            display_name = " ".join(parts)

        user_info = {
            "username": username,
            "email": email,
            "display_name": display_name,
            "permissions": list(self.default_permissions),
            "provider": provider,
            "provider_user_id": provider_user_id,
        }

        logger.info(
            f"Provisioned user: {username} via {provider} "
            f"with permissions: {user_info['permissions']}"
        )

        return user_info

    def get_user(self, username: str) -> Optional[dict]:
        """
        Get existing user information from dserver.

        Args:
            username: Username to look up

        Returns:
            User info dict or None if not found
        """
        # TODO: Implement actual dserver user lookup
        return None

    def update_user(self, username: str, user_info: dict) -> bool:
        """
        Update an existing user's information.

        Args:
            username: Username to update
            user_info: New user information

        Returns:
            True if update successful
        """
        # TODO: Implement actual dserver user update
        logger.info(f"Would update user {username} with: {user_info}")
        return True
