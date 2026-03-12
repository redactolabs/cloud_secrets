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

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from Google Cloud Secret Manager."""
        try:
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            response = self.client.access_secret_version(request={"name": name})
            value = response.payload.data.decode("UTF-8")

            # Track that we've fetched this secret
            self._fetched_secrets.add(secret_name)

            self.env.read_env(io.StringIO(value), overwrite=True)
            self.env.ENVIRON[secret_name] = value

            return value

        except exceptions.NotFound:
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")

    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        parent = f"projects/{self.project_id}"
        secret_path = f"{parent}/secrets/{secret_name}"
        try:
            self.client.get_secret(request={"name": secret_path})
        except exceptions.NotFound:
            try:
                self.client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_name,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
            except exceptions.AlreadyExists:
                pass  # Another process created it; proceed to add_secret_version
        except Exception as e:
            raise ConfigurationError(f"Failed to store secret '{secret_name}': {e}")
        try:
            self.client.add_secret_version(
                request={
                    "parent": secret_path,
                    "payload": {"data": secret_value.encode("UTF-8")},
                }
            )
        except Exception as e:
            raise ConfigurationError(f"Failed to store secret '{secret_name}': {e}")

    def _delete_raw_secret(self, secret_name: str) -> None:
        secret_path = f"projects/{self.project_id}/secrets/{secret_name}"
        try:
            self.client.delete_secret(request={"name": secret_path})
        except exceptions.NotFound:
            pass
        except Exception as e:
            raise ConfigurationError(f"Failed to delete secret '{secret_name}': {e}")
