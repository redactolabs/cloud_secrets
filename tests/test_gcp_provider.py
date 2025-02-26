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
    test_secret = secret_manager.get_secret("REDACTO_TEST1")
    print(
        f"Raw secret value: {test_secret[:50]}..."
    )  # Show just first 50 chars for security

    # Print all environment variables after fetching
    # secret_manager.print_env()

    # Get access to the environment
    env = secret_manager.get_env()

    # Test the first line variable - this should work now
    dummy_value = env("DUMMY")
    print(f"DUMMY value: {dummy_value}")
    assert dummy_value == "DUMMY", "First line DUMMY=DUMMY was not properly read"

    # Test other variables
    env_value = env("ENV")
    print(f"ENV value: {env_value}")
    assert env_value == "staging", "ENV variable not properly parsed from secret"

    # For DEBUG, we need to make sure we check the actual value from the secret
    # which is "False" as a string
    debug_value = env("DEBUG")
    print(f"DEBUG value (raw): {debug_value}")
    assert debug_value == "False", "DEBUG variable not properly parsed from secret"

    # If you want to check the boolean conversion
    debug_bool = env.bool("DEBUG")
    print(f"DEBUG value (boolean): {debug_bool}")
    assert debug_bool is False, "DEBUG boolean conversion is incorrect"

    assert env("REDACTO_TEST1") == "TEST1", "REDACTO_TEST1 not properly read"
    # Test that the original secret is still available
    assert test_secret is not None
    assert isinstance(test_secret, str)

    print("All assertions passed!")
