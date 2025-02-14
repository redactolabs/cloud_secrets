# Cloud Secrets Manager

[![Build Status](https://github.com/redactolabs/cloud_secrets/workflows/Python%20Package/badge.svg)](https://github.com/redactolabs/cloud_secrets/actions)
[![Coverage Status](https://codecov.io/gh/redactolabs/cloud_secrets/branch/main/graph/badge.svg)](https://codecov.io/gh/redactolabs/cloud_secrets)
[![PyPI version](https://badge.fury.io/py/cloud-secrets.svg)](https://badge.fury.io/py/cloud-secrets)
[![Python Versions](https://img.shields.io/pypi/pyversions/cloud-secrets.svg)](https://pypi.org/project/cloud-secrets/)

A flexible, multi-cloud secret management library that supports seamless secret retrieval across different cloud providers and local environments.

## Features

- Support for multiple secret providers:
  - Local Environment
  - AWS Secrets Manager
  - Google Cloud Secret Manager
  - Azure Key Vault
- Easy-to-use interface for secret retrieval
- Type casting support
- Unified error handling

## Installation

```bash
pip install cloud-secrets
```

## Quick Start

### Local Environment Provider

```python
from cloud_secrets import SecretManager

# Use secrets from a local .env file
local_manager = SecretManager(provider_type="local", env_path="/path/to/.env")

# Retrieve a string secret
api_key = local_manager.get_secret("API_KEY")

# Retrieve a boolean secret
debug_mode = local_manager.get_bool("DEBUG")

# Retrieve an integer secret
port = local_manager.get_int("PORT")
```

### AWS Secrets Manager

```python
from cloud_secrets import SecretManager

# Initialize AWS provider
aws_manager = SecretManager(
    provider_type="aws", 
    region_name="us-east-1"
)

# Retrieve a secret
database_password = aws_manager.get_secret("DATABASE_PASSWORD")
```

### Google Cloud Secret Manager

```python
from cloud_secrets import SecretManager

# Initialize GCP provider
gcp_manager = SecretManager(
    provider_type="gcp", 
    project_id="your-gcp-project-id"
)

# Retrieve a dictionary secret with type casting
database_config = gcp_manager.get_dict(
    "DATABASE_CONFIG", 
    field_types={
        "host": str, 
        "port": int, 
        "ssl": bool
    }
)
```

### Azure Key Vault

```python
from cloud_secrets import SecretManager

# Initialize Azure provider
azure_manager = SecretManager(
    provider_type="azure", 
    vault_url="https://your-vault.vault.azure.net/"
)

# Retrieve a secret
azure_secret = azure_manager.get_secret("MY_SECRET")
```

## Django-Environ Integration

The library provides a `get_env()` method that returns the underlying `Env` object from django-environ, allowing for advanced configuration and default value setting.

### Advanced Configuration

```python
from cloud_secrets import SecretManager

# Initialize the secret manager
manager = SecretManager(provider_type="local", env_path="/path/to/.env")

# Access the underlying environ.Env object
env = manager.get_env()

# Set default values and type casting
env.read_env()  # If not already read
env.setup(
    DEBUG=(bool, False),
    DATABASE_URL=(str, 'postgres://localhost/mydatabase'),
    TIMEOUT=(int, 30)
)

# Retrieve values with defaults
debug = env('DEBUG')  # Uses the default False if not set
database_url = env('DATABASE_URL')  # Uses the default URL if not set
timeout = env.int('TIMEOUT')  # Explicitly cast to int with default
```

### Type Casting Examples

```python
# Various type casting methods
str_value = env('MY_STRING', default='default')
bool_value = env.bool('DEBUG', default=False)
int_value = env.int('PORT', default=8000)
float_value = env.float('RATE_LIMIT', default=1.5)
list_value = env.list('ALLOWED_HOSTS', default=['localhost'])

# Complex dictionary parsing
config = env.dict(
    'DATABASE_CONFIG', 
    cast={
        'host': str, 
        'port': int, 
        'enabled': bool
    }
)
```

### Prefix Support

```python
# Using prefixes for namespaced configurations
prefixed_env = env.prefixed('MYAPP_')
database_host = prefixed_env('DATABASE_HOST', default='localhost')
```

## Secret Retrieval Methods

The library supports multiple secret retrieval methods:

- `get_secret(secret_name)`: Retrieve a string secret
- `get_bool(secret_name)`: Retrieve a boolean secret
- `get_int(secret_name)`: Retrieve an integer secret
- `get_float(secret_name)`: Retrieve a float secret
- `get_list(secret_name)`: Retrieve a list secret
- `get_dict(secret_name, field_types)`: Retrieve a dictionary secret with type casting

## Error Handling

The library provides custom exceptions:

- `SecretNotFoundError`: Raised when a secret cannot be retrieved
- `ConfigurationError`: Raised when the provider is misconfigured

```python
from cloud_secrets.common.exceptions import SecretNotFoundError, ConfigurationError

try:
    secret = manager.get_secret("NON_EXISTENT_SECRET")
except SecretNotFoundError as e:
    print(f"Secret not found: {e}")
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```

## Configuration Requirements

### Local Provider
- `env_path`: Path to the .env file

### AWS Provider
- `region_name`: AWS region name

### GCP Provider
- `project_id`: Google Cloud project ID

### Azure Provider
- `vault_url`: Azure Key Vault URL

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Apache License 2.0

## Support

For issues, please file a GitHub issue at https://github.com/redactolabs/cloud_secrets/issues