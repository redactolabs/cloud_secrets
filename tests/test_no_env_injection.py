"""Reading a secret must not touch the environment or logs.

Regression cover for a production credential leak: the GCP provider fed every
fetched secret through ``environ.read_env``, which logs each unparseable line
verbatim. A per-tenant JSON secret was therefore written to Cloud Logging one
field at a time.
"""

import json
import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from cloud_secrets.providers.base import _is_settings_blob
from cloud_secrets.providers.gcp_provider import GCPSecretsProvider

_TENANT_SECRET = json.dumps(
    {"provider": "tatatel", "username": "ASPIRE", "password": "super-secret"}
)


def _provider(value: str) -> GCPSecretsProvider:
    with patch("cloud_secrets.providers.gcp_provider.secretmanager") as mock_sm:
        provider = GCPSecretsProvider(project_id="proj")

    response = MagicMock()
    response.payload.data = value.encode("UTF-8")
    provider.client = MagicMock()
    provider.client.access_secret_version.return_value = response
    return provider


class TestSecretReadIsSideEffectFree:
    def test_success_json_secret_is_not_logged(self, caplog):
        """The leak itself: no part of the value may reach a log record."""
        provider = _provider(_TENANT_SECRET)

        with caplog.at_level(logging.DEBUG):
            provider.get_secret("org-sms-abc")

        emitted = " ".join(record.getMessage() for record in caplog.records)
        assert "super-secret" not in emitted
        assert "ASPIRE" not in emitted
        assert "Invalid line" not in emitted

    def test_success_json_secret_is_not_written_to_environ(self):
        provider = _provider(_TENANT_SECRET)

        provider.get_secret("org-sms-abc")

        assert "org-sms-abc" not in os.environ
        assert "provider" not in os.environ
        assert "username" not in os.environ

    def test_success_value_is_returned_verbatim(self):
        provider = _provider(_TENANT_SECRET)

        assert provider.get_secret("org-sms-abc") == _TENANT_SECRET

    def test_success_dotenv_blob_still_boots(self):
        """Boot paths rely on a dotenv blob being applied; that is retained."""
        provider = _provider("SOME_KEY=some-value\nOTHER_KEY=other")

        provider.get_secret("service-settings")

        assert provider.get_env()("SOME_KEY") == "some-value"

    def test_success_escaped_pem_blob_still_boots(self):
        """A line-shape heuristic would reject this and break boot; JSON-shape
        detection does not."""
        blob = "DB=postgres://x\nKEY=-----BEGIN-----\\nabc\\n-----END-----"
        provider = _provider(blob)

        provider.get_secret("service-settings")

        assert provider.get_env()("DB") == "postgres://x"

    def test_success_cast_works_without_the_environment(self):
        provider = _provider("42")

        assert provider.get_secret("a-number", cast_type="int") == 42


class TestExplicitEnvLoading:
    """The bootstrap path keeps working — it is now opt-in rather than implicit."""

    def test_success_load_secret_into_env_injects(self):
        provider = _provider("BOOTSTRAP_KEY=bootstrap-value")

        env = provider.load_secret_into_env("service-settings")

        assert env("BOOTSTRAP_KEY") == "bootstrap-value"

    def test_success_load_does_not_clobber_existing_settings(self):
        """A settings blob supplies defaults; it does not override the process."""
        os.environ["ALREADY_SET"] = "from-process"
        provider = _provider("ALREADY_SET=from-blob")

        try:
            env = provider.load_secret_into_env("service-settings")
            assert env("ALREADY_SET") == "from-process"
        finally:
            os.environ.pop("ALREADY_SET", None)


class TestOtherProvidersAreAlsoSideEffectFree:
    @pytest.mark.skip(
        reason="AWS settings blobs are JSON, so destructuring is retained for "
        "boot compatibility; removal is the 2.0 item"
    )
    def test_success_aws_does_not_destructure_json_into_environ(self):
        from cloud_secrets.providers.aws_provider import AWSSecretsProvider

        with patch("cloud_secrets.providers.aws_provider.boto3"):
            provider = AWSSecretsProvider(region_name="ap-south-1")

        provider.client = MagicMock()
        provider.client.get_secret_value.return_value = {
            "SecretString": _TENANT_SECRET
        }

        assert provider.get_secret("org-sms-abc") == _TENANT_SECRET
        assert "username" not in os.environ


class TestSettingsBlobDetection:
    """The rule that decides whether a secret is injected.

    Detection is positive — anything not recognised as settings is left alone —
    because read_env logs every line it cannot parse, so a wrong answer in this
    direction writes the secret to the log.
    """

    @pytest.mark.parametrize(
        "label,value,expected",
        [
            ("dotenv blob", "DATABASE_URL=postgres://x\nDEBUG=false\nKEY=abc", True),
            (
                "blob with a multi-line PEM value",
                "DB=postgres://x\nGCP_SA_PRIVATE_KEY=-----BEGIN-----\nMIIabc\n"
                "-----END-----\nDEBUG=false",
                True,
            ),
            ("per-org sms credentials", _TENANT_SECRET, False),
            ("per-org ocr credentials", '{"provider": "azure_di", "api_key": "k"}', False),
            ("bare token (omd-instance-*)", "eyJhbGciOiJIUzI1NiJ9.abc.def", False),
            (
                "connection string with Key=Value pairs",
                "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abc==",
                False,
            ),
            ("single assignment", "JUST_ONE=value", False),
        ],
    )
    def test_success_only_settings_blobs_are_injected(self, label, value, expected):
        assert _is_settings_blob(value) is expected


class TestAzureAlsoInjectsSettingsBlobs:
    """Azure boots the same way GCP does; removing its injection would break it."""

    def _azure(self, value: str):
        from cloud_secrets.providers.azure_provider import AzureSecretsProvider

        with patch("cloud_secrets.providers.azure_provider.SecretClient"), patch(
            "cloud_secrets.providers.azure_provider.DefaultAzureCredential"
        ):
            provider = AzureSecretsProvider(vault_url="https://v.vault.azure.net")

        provider.client = MagicMock()
        provider.client.get_secret.return_value = MagicMock(value=value)
        return provider

    def test_success_settings_blob_is_injected(self):
        provider = self._azure("AZ_KEY=az-value\nAZ_OTHER=other")

        provider.get_secret("service-settings")

        assert provider.get_env()("AZ_KEY") == "az-value"

    def test_success_tenant_secret_is_not_logged_or_injected(self, caplog):
        provider = self._azure(_TENANT_SECRET)

        with caplog.at_level(logging.DEBUG):
            result = provider.get_secret("org-sms-abc")

        assert result == _TENANT_SECRET
        assert "super-secret" not in " ".join(r.getMessage() for r in caplog.records)
