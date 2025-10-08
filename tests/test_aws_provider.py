import os

import pytest

from cloud_secrets.secret_manager import SecretManager


@pytest.fixture
def aws_credentials():
    """Fixture to ensure AWS credentials are set and skip tests if not."""
    if not (
        os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY")
    ):
        pytest.skip(
            "AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) not found in environment - skipping AWS tests"
        )
    yield


def test_aws_provider(aws_credentials):
    """
    Tests the AWSSecretsProvider to ensure it can fetch and parse secrets.
    """
    region = "ap-south-1"
    secret_name = "REDACTO_VENDOR_SETTINGS"
    secret_manager = SecretManager(
        provider_type="aws",
        region_name=region,
    )
    secret_manager.get_secret(secret_name)
    env = secret_manager.get_env()

    assert (
        env("ENV") == "staging"
    ), "ENV variable was not correctly parsed from the secret"

    debug = env.bool("DEBUG")
    assert debug is True, "DEBUG boolean variable was not correctly parsed"

    assert (
        "DATABASE_ENGINE" in env.ENVIRON
    ), "DATABASE_ENGINE key not found in environment"

    print("All AWS provider assertions passed!")
