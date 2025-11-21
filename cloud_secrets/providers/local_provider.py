import os

from cloud_secrets.common.exceptions import CloudSecretsError, ConfigurationError

from .base import BaseSecretProvider


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

    def _load_secret(self, secret_name: str, **kwargs) -> str:
        """Get secret value from the already loaded environment.

        Args:
            secret_name: Name of the secret to load
        """
        try:
            return self.env(secret_name)
        except Exception as e:
            raise CloudSecretsError(f"Error reading secret {secret_name}: {str(e)}")
