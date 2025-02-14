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
        """Get raw secret from environment file."""
        try:
            with open(self.env_path, "r") as f:
                return f.read()
        except Exception as e:
            raise CloudSecretsError(f"Error reading environment file: {str(e)}")
