import os

import pytest

from cloud_secrets.secret_manager import SecretManager


@pytest.fixture
def gcp_credentials():
    """Fixture to handle GCP credentials setup and cleanup."""
    project_id = os.environ.get("GCP_PROJECT_ID")
    if not project_id:
        pytest.skip("GCP_PROJECT_ID environment variable not set - skipping GCP tests")

    creds_path = "tests/staging.json"

    if not os.path.exists(creds_path):
        pytest.skip(
            f"GCP credentials file not found at {creds_path} - skipping GCP tests"
        )

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = creds_path
    yield

    if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
        del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]


def test_gcp_provider_env_file_secret(gcp_credentials):
    """Test retrieving a .env file format secret which returns a dictionary."""
    project_id = os.environ.get("GCP_PROJECT_ID")
    secret_name = os.environ.get("GCP_SECRET_NAME")

    if not secret_name:
        pytest.skip("GCP_SECRET_NAME environment variable not set")

    secret_manager = SecretManager(
        provider_type="gcp",
        project_id=project_id,
    )
    secret_manager.get_secret(secret_name)

    env = secret_manager.get_env()

    dummy_value = env("DUMMY")
    assert dummy_value == "DUMMY", "DUMMY variable should be properly parsed"

    env_value = env("ENV")
    assert env_value == "staging", "ENV variable should be properly parsed"

    debug_value = env("DEBUG")
    assert debug_value == "False", "DEBUG variable should be 'False' as string"

    debug_bool = env.bool("DEBUG")
    assert debug_bool is False, "DEBUG boolean conversion should work"


def test_gcp_provider_raw_secret(gcp_credentials):
    """Test retrieving a raw string secret which returns a string value."""
    project_id = os.environ.get("GCP_PROJECT_ID")
    secret_name = os.environ.get("GCP_RAW_SECRET_NAME")

    if not secret_name:
        pytest.skip(
            "GCP_RAW_SECRET_NAME environment variable not set - skipping raw secret test"
        )

    secret_manager = SecretManager(
        provider_type="gcp",
        project_id=project_id,
    )
    raw_secret = secret_manager.get_secret(
        secret_name,
        is_env=False,
    )

    assert isinstance(raw_secret, str), "Raw secret should be a string"
    assert (
        raw_secret == "test_raw_string_value"
    ), "Raw secret should match the expected test value"
