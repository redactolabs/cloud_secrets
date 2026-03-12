import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from google.api_core import exceptions as gcp_exceptions
from azure.core.exceptions import ResourceNotFoundError

from cloud_secrets import SecretManager
from cloud_secrets.providers.local_provider import LocalEnvProvider
from cloud_secrets.providers.aws_provider import AWSSecretsProvider
from cloud_secrets.providers.gcp_provider import GCPSecretsProvider
from cloud_secrets.providers.azure_provider import AzureSecretsProvider
from cloud_secrets.common.exceptions import ConfigurationError, SecretNotFoundError


# ── Local provider tests ──────────────────────────────────────────────


class TestLocalSetDelete:
    def test_set_and_get_secret(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        provider.set_secret("NEW_KEY", "new_value")
        assert provider.get_secret("NEW_KEY") == "new_value"

    def test_set_and_get_int(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        provider.set_secret("MY_PORT", "8080")
        assert provider.get_int("MY_PORT") == 8080

    def test_delete_secret(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        provider.set_secret("TO_DELETE", "gone_soon")
        assert provider.get_secret("TO_DELETE") == "gone_soon"
        provider.delete_secret("TO_DELETE")
        # After deletion from sidecar, secret is not in .env either
        with pytest.raises(SecretNotFoundError):
            provider.get_secret("TO_DELETE")

    def test_delete_nonexistent_secret(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        # Should not raise
        provider.delete_secret("DOES_NOT_EXIST")

    def test_secrets_json_file_created(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        provider.set_secret("FILE_CHECK", "yes")
        secrets_path = Path(env_file).parent / ".secrets.json"
        assert secrets_path.exists()

    def test_corrupt_secrets_json(self, env_file):
        secrets_path = Path(env_file).parent / ".secrets.json"
        secrets_path.write_text("not valid json{{{")
        provider = LocalEnvProvider(env_path=env_file)
        with pytest.raises(ConfigurationError, match="Corrupt secrets file"):
            provider.get_secret("ANY_KEY")


# ── AWS provider tests ────────────────────────────────────────────────


class TestAWSSetDelete:
    def test_set_secret_existing(self, mock_aws_client):
        provider = AWSSecretsProvider(region_name="us-east-1")
        provider._store_raw_secret("my-secret", "my-value")
        mock_aws_client.put_secret_value.assert_called_once_with(
            SecretId="my-secret", SecretString="my-value"
        )

    def test_set_secret_new(self, mock_aws_client):
        error_response = {"Error": {"Code": "ResourceNotFoundException", "Message": ""}}
        exc = ClientError(error_response, "PutSecretValue")

        # Simulate ResourceNotFoundException on put_secret_value
        mock_aws_client.put_secret_value.side_effect = exc
        mock_aws_client.exceptions.ResourceNotFoundException = type(exc)

        provider = AWSSecretsProvider(region_name="us-east-1")
        provider._store_raw_secret("new-secret", "new-value")

        mock_aws_client.create_secret.assert_called_once_with(
            Name="new-secret", SecretString="new-value"
        )

    def test_delete_secret(self, mock_aws_client):
        provider = AWSSecretsProvider(region_name="us-east-1")
        provider._delete_raw_secret("my-secret")
        mock_aws_client.delete_secret.assert_called_once_with(
            SecretId="my-secret", ForceDeleteWithoutRecovery=True
        )

    def test_delete_nonexistent(self, mock_aws_client):
        error_response = {"Error": {"Code": "ResourceNotFoundException", "Message": ""}}
        exc = ClientError(error_response, "DeleteSecret")
        mock_aws_client.delete_secret.side_effect = exc
        mock_aws_client.exceptions.ResourceNotFoundException = type(exc)

        provider = AWSSecretsProvider(region_name="us-east-1")
        # Should not raise
        provider._delete_raw_secret("missing-secret")

    def test_json_blob_round_trip(self, mock_aws_client):
        """Storing a JSON dict and fetching it back returns the raw JSON, not mangled key=value."""
        import json

        original = json.dumps({"csv_connector/abc": {"private_key": "pk123"}})
        mock_aws_client.get_secret_value.return_value = {"SecretString": original}

        provider = AWSSecretsProvider(region_name="us-east-1")
        result = provider._fetch_raw_secret("org-uuid")

        assert result == original
        assert json.loads(result) == {"csv_connector/abc": {"private_key": "pk123"}}

    def test_flat_dict_destructures_env_vars(self, mock_aws_client):
        """A flat dict secret is destructured into env vars AND the raw JSON is returned."""
        import json
        import os

        original = json.dumps({"DB_HOST": "localhost", "DB_PORT": "5432"})
        mock_aws_client.get_secret_value.return_value = {"SecretString": original}

        provider = AWSSecretsProvider(region_name="us-east-1")
        try:
            result = provider._fetch_raw_secret("my-bundle")

            # Raw JSON is returned
            assert result == original
            # Individual keys were destructured into env
            assert os.environ.get("DB_HOST") == "localhost"
            assert os.environ.get("DB_PORT") == "5432"
            # The bundle name also maps to the raw JSON
            assert os.environ.get("my-bundle") == original
        finally:
            os.environ.pop("DB_HOST", None)
            os.environ.pop("DB_PORT", None)
            os.environ.pop("my-bundle", None)

    def test_store_secret_create_failure(self, mock_aws_client):
        """create_secret ClientError is wrapped in ConfigurationError."""
        not_found_resp = {"Error": {"Code": "ResourceNotFoundException", "Message": ""}}
        not_found_exc = ClientError(not_found_resp, "PutSecretValue")
        mock_aws_client.put_secret_value.side_effect = not_found_exc
        mock_aws_client.exceptions.ResourceNotFoundException = type(not_found_exc)

        create_error_resp = {
            "Error": {"Code": "AccessDeniedException", "Message": "denied"}
        }
        mock_aws_client.create_secret.side_effect = ClientError(
            create_error_resp, "CreateSecret"
        )

        provider = AWSSecretsProvider(region_name="us-east-1")
        with pytest.raises(ConfigurationError, match="Failed to store secret"):
            provider._store_raw_secret("forbidden-secret", "value")


# ── GCP provider tests ────────────────────────────────────────────────


class TestGCPSetDelete:
    def test_set_secret_existing(self, mock_gcp_client):
        client_instance = mock_gcp_client.return_value
        provider = GCPSecretsProvider(project_id="test-project")

        provider._store_raw_secret("my-secret", "my-value")

        client_instance.get_secret.assert_called_once_with(
            request={"name": "projects/test-project/secrets/my-secret"}
        )
        client_instance.add_secret_version.assert_called_once_with(
            request={
                "parent": "projects/test-project/secrets/my-secret",
                "payload": {"data": b"my-value"},
            }
        )
        # create_secret should NOT have been called
        client_instance.create_secret.assert_not_called()

    def test_set_secret_new(self, mock_gcp_client):
        client_instance = mock_gcp_client.return_value
        client_instance.get_secret.side_effect = gcp_exceptions.NotFound("not found")

        provider = GCPSecretsProvider(project_id="test-project")
        provider._store_raw_secret("new-secret", "new-value")

        client_instance.create_secret.assert_called_once_with(
            request={
                "parent": "projects/test-project",
                "secret_id": "new-secret",
                "secret": {"replication": {"automatic": {}}},
            }
        )
        client_instance.add_secret_version.assert_called_once()

    def test_set_secret_already_exists_race(self, mock_gcp_client):
        """Another process created the secret between get and create."""
        client_instance = mock_gcp_client.return_value
        client_instance.get_secret.side_effect = gcp_exceptions.NotFound("not found")
        client_instance.create_secret.side_effect = gcp_exceptions.AlreadyExists(
            "exists"
        )

        provider = GCPSecretsProvider(project_id="test-project")
        provider._store_raw_secret("race-secret", "race-value")

        client_instance.add_secret_version.assert_called_once()

    def test_delete_secret(self, mock_gcp_client):
        client_instance = mock_gcp_client.return_value
        provider = GCPSecretsProvider(project_id="test-project")
        provider._delete_raw_secret("my-secret")

        client_instance.delete_secret.assert_called_once_with(
            request={"name": "projects/test-project/secrets/my-secret"}
        )

    def test_delete_nonexistent(self, mock_gcp_client):
        client_instance = mock_gcp_client.return_value
        client_instance.delete_secret.side_effect = gcp_exceptions.NotFound("nope")

        provider = GCPSecretsProvider(project_id="test-project")
        # Should not raise
        provider._delete_raw_secret("missing-secret")


# ── Azure provider tests ─────────────────────────────────────────────


class TestAzureSetDelete:
    @pytest.fixture
    def azure_provider(self):
        with (
            patch("cloud_secrets.providers.azure_provider.DefaultAzureCredential"),
            patch("cloud_secrets.providers.azure_provider.SecretClient") as mock_cls,
        ):
            client = MagicMock()
            mock_cls.return_value = client
            provider = AzureSecretsProvider(vault_url="https://test.vault.azure.net/")
            yield provider, client

    def test_set_secret(self, azure_provider):
        provider, client = azure_provider
        provider._store_raw_secret("my-secret", "my-value")
        client.set_secret.assert_called_once_with("my-secret", "my-value")

    def test_delete_secret(self, azure_provider):
        provider, client = azure_provider
        provider._delete_raw_secret("my-secret")
        client.begin_delete_secret.assert_called_once_with("my-secret")

    def test_delete_nonexistent(self, azure_provider):
        provider, client = azure_provider
        client.begin_delete_secret.side_effect = ResourceNotFoundError("nope")
        # Should not raise
        provider._delete_raw_secret("missing-secret")


# ── SecretManager facade tests ───────────────────────────────────────


class TestSecretManagerSetDelete:
    def test_set_secret_via_manager(self, env_file):
        manager = SecretManager(provider_type="local", env_path=env_file)
        manager.set_secret("FACADE_KEY", "facade_value")
        assert manager.get_secret("FACADE_KEY") == "facade_value"

    def test_delete_secret_via_manager(self, env_file):
        manager = SecretManager(provider_type="local", env_path=env_file)
        manager.set_secret("TEMP_KEY", "temp_value")
        manager.delete_secret("TEMP_KEY")
        with pytest.raises(SecretNotFoundError):
            manager.get_secret("TEMP_KEY")
