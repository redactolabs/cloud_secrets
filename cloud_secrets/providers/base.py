"""Base provider implementation."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Mapping, Optional

import environ
from environ import Env

from cloud_secrets.common.exceptions import SecretNotFoundError


class BaseSecretProvider(ABC):
    """Base class for secret providers with environ support."""

    def __init__(self, env_path: Optional[str] = None, **kwargs):
        """Initialize the base provider with environ.

        Args:
            env_path: Optional path to .env file
        """
        self.env = environ.Env()
        self.env_path = env_path

    @abstractmethod
    def _load_secret(self, secret_name: str, **kwargs) -> str:
        """Load secret from provider and populate environment.

        Args:
            secret_name: Name of the secret to load
            **kwargs: Provider-specific parameters
        """

    def get_env(self) -> Env:
        return self.env

    def get_secret(
        self,
        secret_name: str,
        cast_type: str = "str",
        dict_fields: Optional[Mapping[str, Any]] = None,
        **kwargs,
    ) -> Any:
        """Get secret with environ casting support.

        Args:
            secret_name: Name of the secret to retrieve
            cast_type: Type to cast the secret to ('str', 'bool', 'int', 'float', 'list', 'dict')
            dict_fields: Field types for dict casting
            **kwargs: Provider-specific parameters (e.g., is_env, is_json)
        """
        try:
            is_env = kwargs.get("is_env", False)

            secret_data = self._load_secret(secret_name, **kwargs)

            if is_env:
                return secret_data

            if cast_type == "dict" and dict_fields:
                return self.env(secret_name, dict(value=str, cast=dict_fields))

            return getattr(self.env, cast_type)(secret_name)
        except Exception as e:
            raise SecretNotFoundError(
                f"Error retrieving secret {secret_name}: {str(e)}"
            )

    def get_dict(
        self, secret_name: str, field_types: Optional[Mapping[str, Any]] = None
    ) -> Dict:
        """Get secret as dictionary with optional field type casting."""
        return self.get_secret(secret_name, cast_type="dict", dict_fields=field_types)

    def get_list(self, secret_name: str) -> List:
        """Get secret as list."""
        return self.get_secret(secret_name, cast_type="list")

    def get_bool(self, secret_name: str) -> bool:
        """Get secret as boolean."""
        return self.get_secret(secret_name, cast_type="bool")

    def get_int(self, secret_name: str) -> int:
        """Get secret as integer."""
        return self.get_secret(secret_name, cast_type="int")

    def get_float(self, secret_name: str) -> float:
        """Get secret as float."""
        return self.get_secret(secret_name, cast_type="float")
