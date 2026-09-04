import pytest

from cloud_secrets.common.exceptions import SecretNotFoundError
from cloud_secrets.providers.local_provider import LocalEnvProvider


class TestLocalProviderFallback:
    def test_missing_env_file_does_not_raise(self, tmp_path):
        LocalEnvProvider(env_path=str(tmp_path / "absent.env"))

    def test_missing_env_file_falls_back_to_process_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FROM_PROCESS_ENV", "hello")
        provider = LocalEnvProvider(env_path=str(tmp_path / "absent.env"))
        assert provider.get_secret("FROM_PROCESS_ENV") == "hello"

    def test_unknown_secret_raises_not_found(self, tmp_path):
        provider = LocalEnvProvider(env_path=str(tmp_path / "absent.env"))
        with pytest.raises(SecretNotFoundError):
            provider.get_secret("DEFINITELY_NOT_SET_XYZ")

    def test_env_file_used_when_present(self, env_file):
        provider = LocalEnvProvider(env_path=env_file)
        assert provider.get_secret("APP_NAME") == "MyApp"
