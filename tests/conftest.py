import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def sample_env_content():
    """Fixture providing sample environment variable content."""
    return """
APP_NAME=MyApp
DEBUG=true
API_KEY=secret123
PORT=8080
RATE_LIMIT=12.5
ALLOWED_HOSTS=localhost,127.0.0.1
CONFIG=db=postgres;port=5432;debug=True;rate=1.5
"""


@pytest.fixture
def env_file(tmp_path, sample_env_content):
    """
    Fixture creating a temporary .env file with sample content.

    Args:
        tmp_path: pytest temporary directory fixture
        sample_env_content: Content for the env file

    Returns:
        str: Path to the created .env file
    """
    env_path = tmp_path / ".env"
    env_path.write_text(sample_env_content)
    return str(env_path)


@pytest.fixture
def mock_aws_client():
    """
    Fixture mocking AWS Secrets Manager client.

    Returns:
        MagicMock: Mocked AWS client with preset secret value
    """
    with patch("boto3.client") as mock:
        client = MagicMock()
        # Mock the get_secret_value response
        client.get_secret_value.return_value = {"SecretString": "secret123"}
        mock.return_value = client
        yield client


@pytest.fixture
def mock_gcp_client():
    """
    Fixture mocking Google Cloud Secret Manager client.

    Returns:
        MagicMock: Mocked GCP Secret Manager client with preset secret value
    """
    with patch("google.cloud.secretmanager.SecretManagerServiceClient") as mock_client:
        # Create mock client instance
        mock_client_instance = mock_client.return_value

        # Create a more complex mock response
        mock_response = MagicMock()
        mock_payload = MagicMock()
        mock_payload.data = b"secret123"
        mock_response.payload = mock_payload

        # Configure the mock client's access_secret_version method
        mock_client_instance.access_secret_version.return_value = mock_response

        yield mock_client


@pytest.fixture
def mock_azure_credential():
    """
    Fixture mocking Azure DefaultAzureCredential.

    Returns:
        MagicMock: Mocked Azure credential
    """
    with patch("azure.identity.DefaultAzureCredential") as mock:
        credential = MagicMock()
        mock.return_value = credential
        yield credential


@pytest.fixture
def mock_azure_client(mock_azure_credential):
    """
    Fixture mocking Azure Key Vault SecretClient.

    Args:
        mock_azure_credential: Mocked Azure credential fixture

    Returns:
        MagicMock: Mocked Azure Secret Client with preset secret value
    """
    with patch("azure.keyvault.secrets.SecretClient") as mock:
        client = MagicMock()
        secret = MagicMock()
        secret.value = "secret123"
        client.get_secret.return_value = secret
        mock.return_value = client
        yield client
