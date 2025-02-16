import os
import pytest
from cloud_secrets.secret_manager import SecretManager


@pytest.fixture
def gcp_credentials():
    """Fixture to handle GCP credentials setup and cleanup."""
    creds_path = "tests/staging.json"

    if not os.path.exists(creds_path):
        pytest.skip("staging.json credentials file not found - skipping GCP tests")

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = creds_path
    yield
    if "GOOGLE_APPLICATION_CREDENTIALS" in os.environ:
        del os.environ["GOOGLE_APPLICATION_CREDENTIALS"]


def test_gcp_provider(gcp_credentials):
    test_project_id = "redacto-staging-445807"
    secret_manager = SecretManager(
        provider_type="gcp",
        project_id=test_project_id,  # Replace with your staging project ID
    )

    # Test fetching an existing secret
    test_secret = secret_manager.get_secret("REDACTO_USER_SETTINGS")
    assert test_secret is not None
    assert isinstance(test_secret, str)
