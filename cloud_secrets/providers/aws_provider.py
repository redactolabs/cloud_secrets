import io
import json

import boto3
from botocore.exceptions import ClientError

from cloud_secrets.common.exceptions import (
    ConfigurationError,
    SecretNotFoundError,
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
                service_name="secretsmanager",
                region_name=self.region_name,
            )
        except Exception as e:
            raise ConfigurationError(
                f"Failed to initialize AWS Secrets Manager: {str(e)}"
            )

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Fetch raw secret from AWS Secrets Manager."""
        try:
            response = self.client.get_secret_value(SecretId=secret_name)

            if "SecretString" not in response:
                raise SecretNotFoundError(f"Secret {secret_name} not found")

            secret = response["SecretString"]
            try:
                secret_data = json.loads(secret)
                if isinstance(secret_data, dict):
                    # Destructure flat dicts into individual env vars
                    content = "\n".join(
                        [f"{key}={val}" for key, val in secret_data.items()]
                    )
                    self.env.read_env(io.StringIO(content))
            except json.JSONDecodeError:
                pass

            # Always store and return the raw value
            self.env.ENVIRON[secret_name] = secret
            return secret
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                raise SecretNotFoundError(f"Secret {secret_name} not found")
            raise ConfigurationError(f"Error retrieving secret: {str(e)}")

    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        try:
            self.client.put_secret_value(
                SecretId=secret_name, SecretString=secret_value
            )
        except self.client.exceptions.ResourceNotFoundException:
            try:
                self.client.create_secret(Name=secret_name, SecretString=secret_value)
            except ClientError as e:
                raise ConfigurationError(f"Failed to store secret '{secret_name}': {e}")
        except ClientError as e:
            raise ConfigurationError(f"Failed to store secret '{secret_name}': {e}")

    def _delete_raw_secret(self, secret_name: str) -> None:
        try:
            self.client.delete_secret(
                SecretId=secret_name, ForceDeleteWithoutRecovery=True
            )
        except self.client.exceptions.ResourceNotFoundException:
            pass
        except ClientError as e:
            raise ConfigurationError(f"Failed to delete secret '{secret_name}': {e}")
