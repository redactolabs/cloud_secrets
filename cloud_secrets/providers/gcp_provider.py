# cloud_secrets/providers/gcp_provider.py
import io

from google.api_core import exceptions
from google.cloud import secretmanager

from cloud_secrets.common.exceptions import (
    ConfigurationError,
    SecretNotFoundError,
)

from .base import BaseSecretProvider


class GCPSecretsProvider(BaseSecretProvider):
    """Google Cloud Secret Manager provider."""

    def __init__(self, **kwargs):
        """Initialize Google Cloud Secret Manager client."""
        super().__init__()
        try:
            self.project_id = kwargs.get("project_id")

            if not self.project_id:
                raise ConfigurationError("GCP project_id is required")

            self.client = secretmanager.SecretManagerServiceClient()
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize GCP Secret Manager: {str(e)}"
            )

    def _load_secret(self, secret_name: str, is_env: bool = True, **kwargs) -> str:
        """Load secret from Google Cloud Secret Manager and populate environment.

        Args:
            secret_name: Name of the secret to load
            is_env: If True, parse secret as .env file format; if False, treat as raw value
        """
        name = None
        try:
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            response = self.client.access_secret_version(request={"name": name})
            value = response.payload.data.decode("UTF-8")

            if is_env:
                self.env.read_env(io.StringIO(value), overwrite=True)
            else:
                self.env.ENVIRON[secret_name] = value

            return value
        except exceptions.NotFound:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            print(f"Exception {e}")
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")
