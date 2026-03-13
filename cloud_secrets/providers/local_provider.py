import json
import os
from pathlib import Path

from .base import BaseSecretProvider
from cloud_secrets.common.exceptions import ConfigurationError, SecretNotFoundError


class LocalEnvProvider(BaseSecretProvider):
    """Local environment file provider."""

    def __init__(self, **kwargs):
        """Initialize local environment provider."""
        super().__init__()
        self.env_path = kwargs.get("env_path", ".env")
        if not os.path.exists(self.env_path):
            raise ConfigurationError(f"Environment file not found: {self.env_path}")
        try:
            self.env.read_env(self.env_path)
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize local provider: {str(e)}")

    def _get_secrets_file_path(self) -> Path:
        return Path(self.env_path).parent / ".secrets.json"

    def _load_secrets_file(self) -> dict:
        path = self._get_secrets_file_path()
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            raise ConfigurationError(f"Corrupt secrets file: {path}")

    def _save_secrets_file(self, data: dict) -> None:
        path = self._get_secrets_file_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Check JSON sidecar first, then fall back to .env."""
        secrets = self._load_secrets_file()
        if secret_name in secrets:
            self.env.ENVIRON[secret_name] = secrets[secret_name]
            return secrets[secret_name]
        try:
            return self.env(secret_name)
        except Exception as e:
            raise SecretNotFoundError(f"Secret {secret_name} not found")

    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        secrets = self._load_secrets_file()
        secrets[secret_name] = secret_value
        self._save_secrets_file(secrets)

    def _delete_raw_secret(self, secret_name: str) -> None:
        secrets = self._load_secrets_file()
        secrets.pop(secret_name, None)
        self._save_secrets_file(secrets)
        self.env.ENVIRON.pop(secret_name, None)
