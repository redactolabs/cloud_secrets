# cloud_secrets/providers/azure_provider.py
import io

from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from .base import BaseSecretProvider
from cloud_secrets.common.exceptions import (
    SecretNotFoundError,
    ConfigurationError,
)


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

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from Azure Key Vault."""
        try:
            response = self.client.get_secret(secret_name)
            # Create an env file format that environ can parse
            self.env.read_env(io.StringIO(f"{secret_name}={response.value}"))
            return response.value
        except ResourceNotFoundError:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")
