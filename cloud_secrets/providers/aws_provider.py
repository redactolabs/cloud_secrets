import io

import boto3
from botocore.exceptions import ClientError
from cloud_secrets.common.exceptions import (
    SecretNotFoundError,
    ConfigurationError,
)
from cloud_secrets.providers.base import BaseSecretProvider


class AWSSecretsProvider(BaseSecretProvider):
    """AWS Secrets Manager provider."""

    def __init__(self, **kwargs):
        """Initialize AWS Secrets Manager client."""
        super().__init__(**kwargs)
        try:
            self.region_name = kwargs.get("region_name", "us-east-1")
            self.client = boto3.client(
                "secretsmanager",
                region_name=self.region_name,
                aws_access_key_id=kwargs.get("aws_access_key_id"),
                aws_secret_access_key=kwargs.get("aws_secret_access_key"),
            )
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize AWS Secrets Manager: {str(e)}"
            )

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from AWS Secrets Manager."""
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            if "SecretString" in response:
                # Create an env file format that environ can parse
                self.env.read_env(
                    io.StringIO(f"{secret_name}={response['SecretString']}")
                )
                return response["SecretString"]
            raise SecretNotFoundError(f"Secret {secret_name} not found")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                raise SecretNotFoundError(f"Secret {secret_name} not found")
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")
