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


# Must mirror django-environ's read_env acceptance EXACTLY: `#` only at column 0,
# and a strict `KEY=` / `export KEY=` with no surrounding whitespace. read_env
# logs every line it rejects verbatim at WARNING ("Invalid line: %s"), so any
# line that passes a looser gate than this but read_env then rejects would leak
# the secret in plaintext. Keep this a strict prefix of read_env's own regex.
_DOTENV_LINE = re.compile(r"\A(?:#|(?:export )?[A-Za-z_0-9]+=)")


def _is_dotenv_blob(text: str) -> bool:
    """Whether text is a MULTI-KEY dotenv config blob — every non-blank line is a
    comment or KEY=VALUE, and there is more than one assignment. A single
    `KEY=value` line (e.g. `PASSWORD=abc`) is a scalar secret, not a blob: it
    stays verbatim under the Key Vault secret name instead of being split into
    an env key. JSON and other scalar values fail the per-line match."""
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or not all(_DOTENV_LINE.match(line) for line in lines):
        return False
    assignments = [line for line in lines if not line.lstrip().startswith("#")]
    return len(assignments) > 1


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
            # Store verbatim so BaseSecretProvider.get_secret() reads it back by
            # name: Key Vault names contain dashes, which read_env can't use as a
            # dotenv key, so the value can't round-trip through read_env.
            self.env.ENVIRON[secret_name] = value
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
