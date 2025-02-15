import pytest

from cloud_secrets import SecretManager
from cloud_secrets.common.exceptions import ConfigurationError
from cloud_secrets.providers.aws_provider import AWSSecretsProvider
from cloud_secrets.providers.gcp_provider import GCPSecretsProvider
from cloud_secrets.providers.azure_provider import AzureSecretsProvider
from cloud_secrets.providers.local_provider import LocalEnvProvider


class TestLocalProvider:
    def test_initialization(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.env_path == env_file

    def test_get_string(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.get_secret("API_KEY") == "secret123"

    def test_get_bool(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.get_bool("DEBUG") is True

    def test_get_int(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.get_int("PORT") == 8080

    def test_get_float(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.get_float("RATE_LIMIT") == 12.5

    def test_get_list(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.get_list("ALLOWED_HOSTS") == ["localhost", "127.0.0.1"]

    def test_print(self, env_file):
        # Use secrets from a local .env file
        local_manager = SecretManager(provider_type="local", env_path=env_file)
        local_manager.print_env()

    def test_dict_value(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        result = provider.get_dict(
            "CONFIG", field_types={"db": str, "port": int, "debug": bool, "rate": float}
        )
        assert result == {"db": "postgres", "port": 5432, "debug": True, "rate": 1.5}


class TestSecretManager:
    def test_provider_selection(
        self,
        env_file,
        mock_aws_client,
        mock_gcp_client,
        mock_azure_client,
        mock_azure_credential,
    ):
        # Test Local provider
        manager = SecretManager(provider_type="local", env_path=env_file)
        assert isinstance(manager.provider, LocalEnvProvider)

        # Test AWS provider
        manager = SecretManager(provider_type="aws", region_name="us-east-1")
        assert isinstance(manager.provider, AWSSecretsProvider)

        # Test GCP provider
        manager = SecretManager(provider_type="gcp", project_id="test-project")
        assert isinstance(manager.provider, GCPSecretsProvider)

        # Test Azure provider
        manager = SecretManager(
            provider_type="azure", vault_url="https://test.vault.azure.net/"
        )
        assert isinstance(manager.provider, AzureSecretsProvider)

    def test_invalid_provider(self):
        with pytest.raises(ConfigurationError):
            SecretManager(provider_type="invalid")

    def test_missing_provider_config(self):
        with pytest.raises(ConfigurationError):
            SecretManager(provider_type="gcp")  # Missing project_id

        with pytest.raises(ConfigurationError):
            SecretManager(provider_type="azure")  # Missing vault_url
