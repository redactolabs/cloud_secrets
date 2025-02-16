import os
from .base import BaseSecretProvider
from cloud_secrets.common.exceptions import ConfigurationError, CloudSecretsError


class LocalEnvProvider(BaseSecretProvider):
    """Local environment file provider."""

    def __init__(self, **kwargs):
        """Initialize local environment provider."""
        super().__init__()
        try:
            self.env_path = kwargs.get("env_path", ".env")
            if not os.path.exists(self.env_path):
                raise ConfigurationError(f"Environment file not found: {self.env_path}")
            self.env.read_env(self.env_path)
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize local provider: {str(e)}")

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Get raw secret value from the already loaded environment."""
        try:
            return self.env(secret_name)
        except Exception as e:
            raise CloudSecretsError(f"Error reading secret {secret_name}: {str(e)}")
