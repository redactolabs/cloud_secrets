import json

import pytest
from unittest.mock import MagicMock, patch

from azure.core.exceptions import ResourceNotFoundError

from cloud_secrets.providers.azure_provider import (
    AzureSecretsProvider,
    _is_dotenv_blob,
)
from cloud_secrets.providers.aws_provider import AWSSecretsProvider
from cloud_secrets.common.exceptions import SecretNotFoundError


@pytest.fixture
def azure_provider():
    with (
        patch("cloud_secrets.providers.azure_provider.DefaultAzureCredential"),
        patch("cloud_secrets.providers.azure_provider.SecretClient") as mock_cls,
    ):
        client = MagicMock()
        mock_cls.return_value = client
        provider = AzureSecretsProvider(vault_url="https://test.vault.azure.net/")
        yield provider, client


def _stored(client, value):
    secret = MagicMock()
    secret.value = value
    client.get_secret.return_value = secret


class TestAzureReadBack:
    def test_get_secret_json_value_returned_verbatim(self, azure_provider):
        provider, client = azure_provider
        blob = json.dumps(
            {"access_key_id": "AKIA123", "secret_access_key": "abc/def+GHI=jkl"}
        )
        _stored(client, blob)

        result = provider.get_secret("csv-connector-org-config")

        client.get_secret.assert_called_once_with("csv-connector-org-config")
        assert result == blob
        assert json.loads(result)["secret_access_key"] == "abc/def+GHI=jkl"

    def test_get_secret_dotenv_blob_exposes_keys(self, azure_provider):
        provider, client = azure_provider
        _stored(client, "APP_NAME=MyApp\nPORT=8080\n")

        provider.get_secret("app-config")

        env = provider.get_env()
        assert env.str("APP_NAME") == "MyApp"
        assert env.int("PORT") == 8080

    def test_get_secret_single_line_scalar_not_destructured(self, azure_provider):
        provider, client = azure_provider
        conn = "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abc=="
        _stored(client, conn)

        result = provider.get_secret("storage-conn")

        assert result == conn
        assert "AccountName" not in provider.get_env().ENVIRON

    def test_get_secret_missing_raises_not_found(self, azure_provider):
        provider, client = azure_provider
        client.get_secret.side_effect = ResourceNotFoundError("nope")

        with pytest.raises(SecretNotFoundError):
            provider.get_secret("missing")


class TestIsDotenvBlob:
    def test_multi_line_assignments_is_blob(self):
        assert _is_dotenv_blob("A=1\nB=2") is True

    def test_single_assignment_is_not_blob(self):
        assert _is_dotenv_blob("A=1") is False

    def test_json_scalar_is_not_blob(self):
        assert _is_dotenv_blob('{"a": "b", "c": "d"}') is False

    def test_spaces_around_equals_is_not_blob(self):
        assert _is_dotenv_blob("API_KEY = sk-live-x\nB=2") is False

    def test_indented_line_is_not_blob(self):
        assert _is_dotenv_blob("A=1\n  DB_PASSWORD=x") is False


class TestAzureNameNormalization:
    def test_underscores_mapped_to_dashes(self, azure_provider):
        provider, client = azure_provider
        assert provider._canonical_name("csv_connector_a_b") == "csv-connector-a-b"

    def test_hyphenated_uuid_name_unchanged(self, azure_provider):
        provider, _ = azure_provider
        name = "csv-connector-0f1e2d3c-4b5a-6978-8899-aabbccddeeff"
        assert provider._canonical_name(name) == name

    def test_set_get_delete_resolve_to_dashed_key(self, azure_provider):
        provider, client = azure_provider
        _stored(client, "v")

        provider.set_secret("csv_connector_a_b", "v")
        provider.get_secret("csv_connector_a_b")
        provider.delete_secret("csv_connector_a_b")

        client.set_secret.assert_called_once_with("csv-connector-a-b", "v")
        client.get_secret.assert_called_once_with("csv-connector-a-b")
        client.begin_delete_secret.assert_called_once_with("csv-connector-a-b")


class TestNonAzurePreservesUnderscores:
    def test_aws_name_unchanged(self):
        with patch("cloud_secrets.providers.aws_provider.boto3.client"):
            provider = AWSSecretsProvider(region_name="us-east-1")
        assert provider._canonical_name("csv_connector_a_b") == "csv_connector_a_b"
