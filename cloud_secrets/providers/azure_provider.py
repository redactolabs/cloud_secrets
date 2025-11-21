# cloud_secrets/providers/azure_provider.py
import io

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from cloud_secrets.common.exceptions import (
    ConfigurationError,
    SecretNotFoundError,
)

from .base import BaseSecretProvider


class AzureSecretsProvider(BaseSecretProvider):
    """Azure Key Vault provider."""

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

    def _load_secret(self, secret_name: str, is_env: bool = True, **kwargs) -> str:
        """Load secret from Azure Key Vault and populate environment.

        Args:
            secret_name: Name of the secret to load
            is_env: If True, parse secret as .env file format; if False, treat as raw value
        """
        try:
            response = self.client.get_secret(secret_name)

            if is_env:
                self.env.read_env(io.StringIO(response.value))
            else:
                self.env.ENVIRON[secret_name] = response.value

            return response.value
        except ResourceNotFoundError:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")
