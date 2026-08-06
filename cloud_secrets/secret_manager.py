"""Secret Manager implementation."""

from typing import Any

from environ import Env

from cloud_secrets.common.exceptions import ConfigurationError
from cloud_secrets.providers.aws_provider import AWSSecretsProvider
from cloud_secrets.providers.gcp_provider import GCPSecretsProvider
from cloud_secrets.providers.azure_provider import AzureSecretsProvider
from cloud_secrets.providers.local_provider import LocalEnvProvider
from cloud_secrets.providers.base import BaseSecretProvider


class SecretManager:
    """Main class for managing secrets across different providers."""

    PROVIDERS = {
        "aws": AWSSecretsProvider,
        "gcp": GCPSecretsProvider,
        "azure": AzureSecretsProvider,
        "local": LocalEnvProvider,
    }

    def __init__(self, provider_type: str, **kwargs):
        """Initialize the secret manager with specified provider.

        Args:
            provider_type: Type of provider ('aws', 'gcp', 'azure', or 'local')
            **kwargs: Provider-specific configuration options

        Raises:
            ConfigurationError: If provider type is invalid or configuration is incomplete
        """
        if provider_type not in self.PROVIDERS:
            raise ConfigurationError(f"Invalid provider type: {provider_type}")

        self.provider: BaseSecretProvider = self.PROVIDERS[provider_type](**kwargs)

    def get_secret(self, secret_name: str, **kwargs) -> Any:
        """Return a secret's value.

        Read-only: the value is not parsed, not written to ``os.environ``, and
        not logged. Use this for per-tenant secrets.
        """
        return self.provider.get_secret(secret_name, **kwargs)

    def load_secret_into_env(self, secret_name: str) -> Env:
        """Load a dotenv-formatted settings blob into the environment.

        The bootstrap path, for a service loading its own configuration. Never
        call this with a per-tenant secret: its contents would be parsed as
        configuration and could overwrite real settings.
        """
        return self.provider.load_secret_into_env(secret_name)

    def set_secret(self, secret_name: str, secret_value: str) -> None:
        """Create or update a secret."""
        self.provider.set_secret(secret_name, secret_value)

    def delete_secret(self, secret_name: str) -> None:
        """Delete a secret. No-op if it doesn't exist."""
        self.provider.delete_secret(secret_name)

    def get_env(self) -> Env:
        return self.provider.get_env()

    def print_env(self):
        env: Env = self.get_env()
        # dump all the env variables
        print(f"Let's print all env")
        for key, val in env.ENVIRON.items():
            print(f"⚙️ {key} == {val}")
