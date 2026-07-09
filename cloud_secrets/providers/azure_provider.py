# cloud_secrets/providers/azure_provider.py
import io
import re

from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from .base import BaseSecretProvider
from cloud_secrets.common.exceptions import (
    SecretNotFoundError,
    ConfigurationError,
)


# Matches a dotenv line: a comment, or `KEY=` (optionally `export KEY=`).
_DOTENV_LINE = re.compile(r"^\s*(?:#|(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=)")


def _is_dotenv_blob(text: str) -> bool:
    """Whether text is a dotenv config blob (every non-blank line is KEY=VALUE),
    as opposed to a JSON or scalar secret value."""
    lines = [line for line in text.splitlines() if line.strip()]
    return bool(lines) and all(_DOTENV_LINE.match(line) for line in lines)


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
            value = response.value or ""
            # get_secret() reads the value back by name; store it verbatim because
            # Key Vault names contain dashes, which read_env cannot use as a key.
            self.env.ENVIRON[secret_name] = value
            # Config blobs are dotenv; parse them so get_env() exposes each key.
            if _is_dotenv_blob(value):
                self.env.read_env(io.StringIO(value))
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
