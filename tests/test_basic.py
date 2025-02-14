"""Basic tests to verify package structure and imports."""

import pytest

from cloud_secrets import SecretManager
from cloud_secrets.common.exceptions import ConfigurationError, CloudSecretsError
from cloud_secrets.providers.aws_provider import AWSSecretsProvider
from cloud_secrets.providers.azure_provider import AzureSecretsProvider
from cloud_secrets.providers.gcp_provider import GCPSecretsProvider
from cloud_secrets.providers.local_provider import LocalEnvProvider


def test_package_imports():
    """Test that we can import our package components."""
    assert AWSSecretsProvider
    assert GCPSecretsProvider
    assert AzureSecretsProvider
    assert LocalEnvProvider


def test_error_inheritance():
    """Test that our custom exceptions are properly defined."""
    assert issubclass(ConfigurationError, CloudSecretsError)
    assert issubclass(CloudSecretsError, Exception)


def test_secret_manager_initialization():
    """Test that SecretManager raises proper errors."""
    with pytest.raises(ConfigurationError, match="Invalid provider type"):
        SecretManager(provider_type="invalid_provider")
