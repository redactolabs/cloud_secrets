import json
from pathlib import Path
from typing import Any, Callable

import hvac
from hvac.exceptions import Forbidden, InvalidPath, Unauthorized

from cloud_secrets.common.exceptions import (
    CloudSecretsError,
    ConfigurationError,
    SecretNotFoundError,
)
from cloud_secrets.providers.base import BaseSecretProvider

SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

DEFAULT_KV_MOUNT = "secret"
DEFAULT_AUTH_MOUNT = "kubernetes"

_RAW_FIELD = "__raw__"


def _to_fields(secret_value: str) -> dict[str, Any]:
    """Map the library's string value onto the field map KV v2 stores.

    A JSON object becomes one Vault field per key, so `vault kv get` renders it
    readably and an operator can set a single key. Anything else — including an
    object that itself uses the reserved key, which would otherwise collide with
    a wrapped string — round-trips whole through that one field.
    """
    try:
        parsed = json.loads(secret_value)
    except ValueError:
        return {_RAW_FIELD: secret_value}
    if isinstance(parsed, dict) and _RAW_FIELD not in parsed:
        return parsed
    return {_RAW_FIELD: secret_value}


def _from_fields(fields: dict[str, Any]) -> str:
    """Recover the string `_to_fields` was given.

    A lone reserved field holding a string is that string; every other field map
    is the JSON object it represents.
    """
    if list(fields) == [_RAW_FIELD] and isinstance(fields[_RAW_FIELD], str):
        return fields[_RAW_FIELD]
    return json.dumps(fields)


class VaultSecretsProvider(BaseSecretProvider):
    """HashiCorp Vault and OpenBao KV v2 provider.

    Authenticates with the Kubernetes auth method when `role` is given, otherwise
    with a token — `token`, else hvac's own `VAULT_TOKEN` lookup. Leaving both
    unset is a configuration error rather than an anonymous client.

    Accepts `namespace` for the editions that partition (Vault Enterprise, HCP
    Dedicated, whose top-level namespace is `admin`) and omits the header
    entirely when it is unset, which is what a Community cluster requires.
    `verify` takes a CA bundle path for a cluster behind a private CA.

    Unlike the cloud providers this never spreads a fetched secret's keys into
    the process environment. The raw value is still placed under the secret's own
    name because `BaseSecretProvider.get_secret` reads it back from there, and
    `environ.Env.ENVIRON` is `os.environ` — so a caller that needs the value out
    of the environment must pop that one key itself.
    """

    def __init__(self, **kwargs):
        """Raises ConfigurationError for a missing url, missing credentials, or a
        failed login."""
        super().__init__(**kwargs)
        url = kwargs.get("url")
        if not url:
            raise ConfigurationError("Vault url is required")

        self.mount_point = kwargs.get("mount_point", DEFAULT_KV_MOUNT)
        self._role = kwargs.get("role")
        self._auth_mount_point = kwargs.get("auth_mount_point", DEFAULT_AUTH_MOUNT)
        self._may_relogin = True

        try:
            self.client = hvac.Client(
                url=url,
                token=kwargs.get("token"),
                namespace=kwargs.get("namespace"),
                verify=kwargs.get("verify"),
            )
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Vault client: {e}")

        self._login()

    def _canonical_name(self, secret_name: str) -> str:
        """Vault paths keep `/`, `_` and `-`, so nothing is rewritten. A `..`
        segment is rejected: requests normalises it away client-side, which would
        walk the request out of the configured mount and onto any endpoint the
        token can reach."""
        if ".." in secret_name.split("/"):
            raise CloudSecretsError(
                f"Secret name '{secret_name}' escapes the configured mount"
            )
        return secret_name

    def _login(self) -> None:
        """Exchange the pod's service account token for a Vault token.

        Reads the service account token from disk on every call: Kubernetes
        rotates it, so a cached copy expires with the projected volume.
        """
        if not self._role:
            if not self.client.token:
                raise ConfigurationError(
                    "Vault needs either a Kubernetes role or a token"
                )
            return

        try:
            jwt = Path(SERVICE_ACCOUNT_TOKEN_PATH).read_text()
        except OSError as e:
            raise ConfigurationError(
                f"Vault role '{self._role}' needs a Kubernetes service account "
                f"token at {SERVICE_ACCOUNT_TOKEN_PATH}: {e}"
            )

        try:
            self.client.auth.kubernetes.login(
                role=self._role, jwt=jwt, mount_point=self._auth_mount_point
            )
        except Exception as e:
            raise ConfigurationError(
                f"Vault Kubernetes login for role '{self._role}' failed: "
                f"{type(e).__name__}"
            )

    def _with_relogin(self, action: Callable[[], Any]) -> Any:
        """Run a Vault call, logging in again once if the token has expired.

        A Kubernetes-auth token has its own TTL and outlives neither the pod nor
        that TTL, so a client held for the life of a process has to be able to
        authenticate again. Vault answers a policy denial with the same 403, so
        the retry is latched: it is spent on the first denial and only restored
        by a call that succeeds. Without that, a narrowed policy would turn every
        read across the fleet into a login, and each login costs Vault a
        TokenReview against the Kubernetes API server. A static token cannot be
        renewed, so it never retries.
        """
        try:
            result = action()
        except (Forbidden, Unauthorized):
            if not self._role or not self._may_relogin:
                raise
            self._may_relogin = False
            self._login()
            result = action()
        self._may_relogin = True
        return result

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Raises SecretNotFoundError when the path holds no secret. Vault answers
        a mount that does not exist with the same 404, so the message names the
        mount too."""

        def read():
            return self.client.secrets.kv.v2.read_secret_version(
                path=secret_name,
                mount_point=self.mount_point,
                raise_on_deleted_version=True,
            )

        try:
            response = self._with_relogin(read)
        except InvalidPath:
            raise SecretNotFoundError(
                f"Secret {secret_name} not found under mount '{self.mount_point}'"
            )
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {e}")

        value = _from_fields(response["data"]["data"])
        self.env.ENVIRON[secret_name] = value
        return value

    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        def write():
            return self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_name,
                secret=_to_fields(secret_value),
                mount_point=self.mount_point,
            )

        try:
            self._with_relogin(write)
        except Exception as e:
            raise ConfigurationError(
                f"Failed to store secret '{secret_name}': {type(e).__name__}"
            )

    def _delete_raw_secret(self, secret_name: str) -> None:
        def destroy():
            return self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=secret_name, mount_point=self.mount_point
            )

        try:
            self._with_relogin(destroy)
        except InvalidPath:
            pass
        except Exception as e:
            raise ConfigurationError(f"Failed to delete secret '{secret_name}': {e}")
