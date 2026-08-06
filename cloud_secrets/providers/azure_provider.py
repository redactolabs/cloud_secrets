# cloud_secrets/providers/azure_provider.py
import io
import re

from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from .base import BaseSecretProvider, _is_settings_blob
from cloud_secrets.common.exceptions import (
    SecretNotFoundError,
    ConfigurationError,
)


class AzureSecretsProvider(BaseSecretProvider):
    """Azure Key Vault provider."""

    _INVALID_NAME_CHARS = re.compile(r"[^0-9a-zA-Z-]")

    def __init__(self, **kwargs):
        """Initialize Azure Key Vault client."""
        super().__init__()
        try:
            vault_url = kwargs.get("vault_url")
            if not vault_url:
                raise ConfigurationError("Azure vault_url is required")
            credential = DefaultAzureCredential()
            self.client = SecretClient(vault_url=vault_url, credential=credential)
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Azure Key Vault: {str(e)}")

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from Azure Key Vault."""
        try:
            value = self.client.get_secret(secret_name).value

            # Same rule as GCP: only a settings blob is injected.
            if _is_settings_blob(value):
                self.env.read_env(io.StringIO(value), overwrite=False)

            return value
        except ResourceNotFoundError:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")

    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        try:
            self.client.set_secret(secret_name, secret_value)
        except Exception as e:
            raise ConfigurationError(f"Failed to store secret '{secret_name}': {e}")

    def _delete_raw_secret(self, secret_name: str) -> None:
        try:
            self.client.begin_delete_secret(secret_name)
        except ResourceNotFoundError:
            pass
        except Exception as e:
            raise ConfigurationError(f"Failed to delete secret '{secret_name}': {e}")
