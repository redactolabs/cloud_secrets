# cloud_secrets/providers/gcp_provider.py
import io

from google.cloud import secretmanager
from google.api_core import exceptions
from .base import BaseSecretProvider
from cloud_secrets.common.exceptions import (
    SecretNotFoundError,
    ConfigurationError,
)


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

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from Google Cloud Secret Manager."""
        try:
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            response = self.client.access_secret_version(request={"name": name})
            value = response.payload.data.decode("UTF-8")
            # Create an env file format that environ can parse
            self.env.read_env(io.StringIO(f"{secret_name}={value}"))
            return value
        except exceptions.NotFound:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")
