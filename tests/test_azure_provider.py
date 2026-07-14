"""Regression tests for AzureSecretsProvider.get_secret read-back.

The bug this guards: dash-named secrets holding a JSON blob (the vendor CSV
connector's S3/SFTP credentials, keyed `csv-connector-<org>-<config>` on Azure)
came back EMPTY because get_secret round-tripped them through django-environ's
dotenv parser, which rejects dash keys and JSON — and logged the raw secret as
an "Invalid line". Empty creds then surfaced downstream as S3 AccessDenied.

These tests fail if the fix in azure_provider.py is reverted.
"""

import json
from unittest.mock import MagicMock, patch

from azure.core.exceptions import ResourceNotFoundError

from cloud_secrets.providers.azure_provider import _is_dotenv_blob


def _provider_with_secrets(secrets: dict):
    """An AzureSecretsProvider whose Key Vault returns the given {name: value}.

    Patches the module-bound SecretClient/DefaultAzureCredential (bound at
    import, so patching azure.* directly would miss them) and injects a mock
    client. Import is local so a missing azure SDK skips rather than errors the
    whole module.
    """
    from cloud_secrets.providers.azure_provider import AzureSecretsProvider

    def _get(name):
        if name not in secrets:
            raise ResourceNotFoundError(f"{name} not found")
        m = MagicMock()
        m.value = secrets[name]
        return m

    with patch("cloud_secrets.providers.azure_provider.DefaultAzureCredential"), patch(
        "cloud_secrets.providers.azure_provider.SecretClient"
    ) as mock_cls:
        client = MagicMock()
        client.get_secret.side_effect = _get
        mock_cls.return_value = client
        return AzureSecretsProvider(vault_url="https://test.vault.azure.net/")


def test_dash_named_json_secret_returns_verbatim():
    """The CSV-connector case: a dash-named JSON secret must round-trip verbatim
    (this is the exact value that came back empty before the fix)."""
    creds = {
        "access_key_id": "AKIAEXAMPLE",
        "secret_access_key": "s3cr3t/EXAMPLE",
        "bucket": "vendor-csv",
    }
    name = "csv-connector-org-ec7ef774-1c4b-4f38-8823-df654dcf42b3"
    provider = _provider_with_secrets({name: json.dumps(creds)})

    raw = provider.get_secret(name)
    assert json.loads(raw) == creds


def test_multiline_dotenv_blob_still_exposes_keys():
    """A genuine multi-key dotenv config blob is still parsed into env keys."""
    blob = "APP_NAME=MyApp\nDEBUG=true\nPORT=8080"
    provider = _provider_with_secrets({"app-config": blob})

    provider.get_secret("app-config")
    assert provider.env("APP_NAME") == "MyApp"
    assert provider.env.int("PORT") == 8080


def test_single_scalar_key_value_stays_verbatim():
    """A single `KEY=value` line is a scalar, not a blob: returned verbatim and
    NOT split into an env key (CodeRabbit finding)."""
    provider = _provider_with_secrets({"db-password": "PASSWORD=abc"})

    assert provider.get_secret("db-password") == "PASSWORD=abc"
    assert "PASSWORD" not in provider.env.ENVIRON  # never loaded as a key


def test_loose_line_is_not_parsed_so_no_leak():
    """A line read_env would reject (spaces around '=') must NOT pass the gate,
    so it is stored verbatim and never handed to read_env (which would log the
    secret at WARNING). Zaid's security finding."""
    value = "API_KEY = sk-live-supersecret"
    provider = _provider_with_secrets({"api": value})

    assert provider.get_secret("api") == value
    assert "API_KEY" not in provider.env.ENVIRON


def test_is_dotenv_blob_classification():
    """Direct unit coverage of the classifier the fix hinges on."""
    assert _is_dotenv_blob("A=1\nB=2") is True
    assert _is_dotenv_blob("# header\nA=1\nB=2") is True
    assert _is_dotenv_blob("PASSWORD=abc") is False          # single scalar
    assert _is_dotenv_blob("API_KEY = sk-live-x") is False   # loose line
    assert _is_dotenv_blob('{"a": "b"}') is False            # JSON
    assert _is_dotenv_blob("opaque-token") is False          # scalar
    assert _is_dotenv_blob("") is False
