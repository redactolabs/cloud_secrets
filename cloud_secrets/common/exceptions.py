class CloudSecretsError(Exception):
    """Base exception for cloud secrets library."""


class ConfigurationError(CloudSecretsError):
    """Raised when there's an issue with configuration."""


class SecretNotFoundError(CloudSecretsError):
    """Raised when a secret is not found."""


class ProviderNotFoundError(CloudSecretsError):
    """Raised when specified provider is not supported."""
