# cloud_secrets/providers/vault_provider.py
import json
import logging
import os

import requests

from .base import BaseSecretProvider
from cloud_secrets.common.exceptions import (
    ConfigurationError,
    SecretNotFoundError,
)

logger = logging.getLogger(__name__)

_K8S_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class VaultSecretsProvider(BaseSecretProvider):
    """HashiCorp Vault KV v2 provider for on-prem / DC deployments.

    Auth is token-based (VAULT_TOKEN) or Kubernetes auth (VAULT_K8S_ROLE +
    the pod's projected ServiceAccount JWT), matching what bank clusters
    typically allow. Secrets live under ``<mount>/<base_path>/<name>`` as a
    flat KV map: multi-key maps are env blobs (each key becomes an env var),
    a single-key ``{"value": ...}`` map is a scalar secret stored verbatim.
    """

    def __init__(self, **kwargs):
        super().__init__()
        self.vault_url = (
            kwargs.get("vault_url") or os.environ.get("VAULT_ADDR", "")
        ).rstrip("/")
        if not self.vault_url:
            raise ConfigurationError("Vault vault_url (or VAULT_ADDR) is required")

        self.mount_point = kwargs.get(
            "mount_point", os.environ.get("VAULT_KV_MOUNT", "secret")
        )
        self.base_path = (
            kwargs.get("base_path", os.environ.get("VAULT_BASE_PATH", ""))
        ).strip("/")
        # Vault Enterprise namespace (banks commonly use these); empty = none.
        self.namespace = kwargs.get("namespace", os.environ.get("VAULT_NAMESPACE", ""))

        verify = os.environ.get("VAULT_CACERT") or not os.environ.get(
            "VAULT_SKIP_VERIFY"
        )
        self.session = requests.Session()
        self.session.verify = verify
        if self.namespace:
            self.session.headers["X-Vault-Namespace"] = self.namespace

        token = kwargs.get("token") or os.environ.get("VAULT_TOKEN")
        if not token:
            token = self._kubernetes_login(**kwargs)
        self.session.headers["X-Vault-Token"] = token

    def _kubernetes_login(self, **kwargs) -> str:
        role = kwargs.get("k8s_role") or os.environ.get("VAULT_K8S_ROLE")
        if not role:
            raise ConfigurationError(
                "Vault auth requires VAULT_TOKEN or VAULT_K8S_ROLE"
            )
        mount = kwargs.get("k8s_auth_mount") or os.environ.get(
            "VAULT_K8S_AUTH_MOUNT", "kubernetes"
        )
        try:
            with open(_K8S_JWT_PATH) as fh:
                jwt = fh.read().strip()
            resp = self.session.post(
                f"{self.vault_url}/v1/auth/{mount}/login",
                json={"role": role, "jwt": jwt},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()["auth"]["client_token"]
        except Exception as e:
            raise ConfigurationError(f"Vault kubernetes auth failed: {e}")

    def _data_url(self, secret_name: str) -> str:
        path = f"{self.base_path}/{secret_name}" if self.base_path else secret_name
        return f"{self.vault_url}/v1/{self.mount_point}/data/{path}"

    def _metadata_url(self, secret_name: str) -> str:
        path = f"{self.base_path}/{secret_name}" if self.base_path else secret_name
        return f"{self.vault_url}/v1/{self.mount_point}/metadata/{path}"

    def _fetch_raw_secret(self, secret_name: str) -> str:
        try:
            resp = self.session.get(self._data_url(secret_name), timeout=10)
            if resp.status_code == 404:
                raise SecretNotFoundError(f"Secret {secret_name} not found")
            resp.raise_for_status()
            data = resp.json()["data"]["data"]
        except (SecretNotFoundError, ConfigurationError):
            raise
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {e}")

        if not isinstance(data, dict):
            raise ConfigurationError(
                f"Secret {secret_name} is not a KV map: {type(data).__name__}"
            )

        # Scalar secret round-trip shape written by _store_raw_secret.
        if set(data) == {"value"}:
            value = str(data["value"])
            self.env.ENVIRON[secret_name] = value
            return value

        # Env-blob map: expose every key, mirroring the AWS JSON destructuring.
        for key, val in data.items():
            self.env.ENVIRON[str(key)] = str(val)
        raw = json.dumps(data)
        self.env.ENVIRON[secret_name] = raw
        logger.info(
            "vault provider: loaded %d keys from %s/%s",
            len(data),
            self.mount_point,
            secret_name,
        )
        return raw

    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        try:
            resp = self.session.post(
                self._data_url(secret_name),
                json={"data": {"value": secret_value}},
                timeout=10,
            )
            resp.raise_for_status()
        except Exception as e:
            raise ConfigurationError(f"Failed to store secret '{secret_name}': {e}")

    def _delete_raw_secret(self, secret_name: str) -> None:
        try:
            resp = self.session.delete(self._metadata_url(secret_name), timeout=10)
            if resp.status_code not in (204, 404):
                resp.raise_for_status()
        except Exception as e:
            raise ConfigurationError(f"Failed to delete secret '{secret_name}': {e}")
