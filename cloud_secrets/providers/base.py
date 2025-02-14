"""Base provider implementation."""

import environ
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Mapping

from environ import Env

from cloud_secrets.common.exceptions import SecretNotFoundError


class BaseSecretProvider(ABC):
    """Base class for secret providers with environ support."""

    def __init__(self, env_path: Optional[str] = None, **kwargs):
        """Initialize the base provider with environ."""
        self.env = environ.Env()
        self.env_path = env_path

    @abstractmethod
    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret value from provider."""

    def get_env(self) -> Env:
        return self.env

    def get_secret(
        self,
        secret_name: str,
        cast_type: str = "str",
        dict_fields: Optional[Mapping[str, Any]] = None,
        **kwargs,
    ) -> Any:
        """Get secret with environ casting support."""
        try:
            if cast_type == "dict" and dict_fields:
                # Need to wrap the value type and cast configuration
                return self.env(secret_name, dict(value=str, cast=dict_fields))
            return getattr(self.env, cast_type)(secret_name, **kwargs)
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
