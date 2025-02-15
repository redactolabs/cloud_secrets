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
        """Get a secret by name."""
        return self.provider.get_secret(secret_name, **kwargs)

    def get_env(self) -> Env:
        return self.provider.get_env()

    def print_env(self):
        env: Env = self.get_env()
        # dump all the env variables
        print(f"Let's print all env")
        for key, val in env.ENVIRON.items():
            print(f"⚙️ {key} == {val}")
