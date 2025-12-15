"""
User provisioning for OAuth2 authenticated users.

This module handles looking up user records in dserver
after successful OAuth2 authentication.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class UserProvisioner:
    """
    Handle user lookup after OAuth2 authentication.

    This class looks up user accounts in dserver to retrieve
    their permissions after OAuth2 authentication.
    """

    def __init__(
        self,
        auto_provision: bool = False,
        default_permissions: Optional[list] = None,
    ):
        """
        Initialize the user provisioner.

        Args:
            auto_provision: Ignored (auto-provisioning not supported)
            default_permissions: Ignored (permissions come from dserver database)
        """
        pass

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
        Return user info after OAuth2 authentication.

        If the user exists in dserver and their display_name is not set,
        it will be updated from the OAuth2 provider data.

        Note: Users must be pre-registered in dserver via the CLI.
        This method does not create users.

        Args:
            username: Unique username (e.g., ORCID ID)
            email: User's email address
            display_name: User's display name
            given_name: User's first name
            surname: User's last name
            provider: OAuth2 provider name (e.g., "orcid", "github")
            provider_user_id: User ID from the OAuth2 provider

        Returns:
            Dictionary with user info
        """
        # Build display name if not provided
        if not display_name and (given_name or surname):
            parts = [p for p in [given_name, surname] if p]
            display_name = " ".join(parts)

        # Try to update display_name in dserver database if not already set
        if display_name:
            try:
                from dservercore.sql_models import User
                from dservercore import sql_db

                user = User.query.filter_by(username=username).first()
                if user and not user.display_name:
                    user.display_name = display_name
                    sql_db.session.commit()
                    logger.info(f"Updated display_name for user {username}")
            except Exception as e:
                # Don't fail authentication if display_name update fails
                logger.warning(f"Could not update display_name for {username}: {e}")

        user_info = {
            "username": username,
            "email": email,
            "display_name": display_name,
            "provider": provider,
            "provider_user_id": provider_user_id,
        }

        logger.info(f"User {username} authenticated via {provider}")

        return user_info
