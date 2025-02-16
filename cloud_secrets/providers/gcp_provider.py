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
            self._fetched_secrets = set()  # Just track names, not values
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize GCP Secret Manager: {str(e)}"
            )

    def _format_env_value(self, value: str) -> str:
        """Format a value for env file, properly escaping special characters."""
        if " " in value or "\n" in value or '"' in value or "'" in value:
            escaped_value = value.replace('"', '\\"')
            return f'"{escaped_value}"'
        return value

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from Google Cloud Secret Manager."""
        name = None
        try:
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            print(f"Secret Manager trying to read {name}")
            response = self.client.access_secret_version(request={"name": name})
            value = response.payload.data.decode("UTF-8")
            print(f"Secret Manager trying to read {secret_name}")

            # Track that we've fetched this secret
            self._fetched_secrets.add(secret_name)

            # Update env with the new secret while preserving others
            current_env = {k: v for k, v in self.env.ENVIRON.items()}
            current_env[secret_name] = value

            # Build env string with proper formatting for each value
            env_lines = []
            for k, v in current_env.items():
                formatted_value = self._format_env_value(v)
                env_lines.append(f"{k}={formatted_value}")

            env_string = "\n".join(env_lines)
            self.env.read_env(io.StringIO(env_string))

            return value

        except exceptions.NotFound:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            print(f"Exception {e}")
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")
