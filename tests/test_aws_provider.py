import os

import pytest

from cloud_secrets.secret_manager import SecretManager


@pytest.fixture
def aws_credentials():
    """Fixture to ensure AWS credentials and region are set and skip tests if not."""
    if (
        not os.environ.get("AWS_ACCESS_KEY_ID")
        or not os.environ.get("AWS_SECRET_ACCESS_KEY")
        or not os.environ.get("AWS_REGION")
    ):
        pytest.skip(
            "AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION) not found in environment - skipping AWS tests"
        )
    yield


def test_aws_provider_env_json(aws_credentials):
    """
    Tests the AWSSecretsProvider to ensure it can fetch and parse secrets.
    """
    region = os.environ.get("AWS_REGION")
    secret_name = os.environ.get("AWS_SECRET_NAME")

    if not secret_name:
        pytest.skip("AWS_SECRET_NAME environment variable not set")

    secret_manager = SecretManager(
        provider_type="aws",
        region_name=region,
    )
    secret_manager.get_secret(secret_name, is_env=True)
    env = secret_manager.get_env()

    dummy_value = env("DUMMY")
    assert dummy_value == "DUMMY", "DUMMY variable should be properly parsed"

    env_value = env("ENV")
    assert env_value == "staging", "ENV variable should be properly parsed"

    debug_value = env("DEBUG")
    assert debug_value == "True", "DEBUG variable should be 'True' as string"

    debug_bool = env.bool("DEBUG")
    assert debug_bool is True, "DEBUG boolean conversion should work"


def test_aws_provider_raw_secret(aws_credentials):
    """
    Tests the AWSSecretsProvider to ensure it can fetch and parse secrets.
    """
    region = os.environ.get("AWS_REGION")
    secret_name = os.environ.get("AWS_RAW_SECRET_NAME")

    if not secret_name:
        pytest.skip("AWS_RAW_SECRET_NAME environment variable not set")

    secret_manager = SecretManager(
        provider_type="aws",
        region_name=region,
    )
    raw_secret = secret_manager.get_secret(
        secret_name,
        is_env=False,
    )

    assert isinstance(raw_secret, str), "Raw secret should be a string"
    assert (
        raw_secret == "this_is_raw_secret=/"
    ), "Raw secret should match the expected test value"
