import json
import re
import time
from pathlib import Path
from threading import Lock
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

RELOGIN_COOLDOWN_SECONDS = 30.0
"""Floor between two Kubernetes logins on one client.

A token lives orders of magnitude longer than this, so a pod whose token expires
re-authenticates on its very next call. What the floor bounds is the other case:
Vault answers a policy denial with the same 403 as an expired token, so without
it a pod polling a denied path once a second costs Vault sixty logins a minute --
and each one costs a TokenReview against the Kubernetes API server.
"""

_RAW_FIELD = "__raw__"

_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")


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
    """Recover an equivalent JSON document, not the source text.

    A lone reserved field holding a string is that string. Every other field map
    is re-encoded, so key order survives but the original spacing does not, and a
    field another writer stored as a number stays a number.
    """
    if list(fields) == [_RAW_FIELD] and isinstance(fields[_RAW_FIELD], str):
        return fields[_RAW_FIELD]
    return json.dumps(fields, ensure_ascii=False)


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
        self._auth_lock = Lock()
        self._auth_generation = 0
        self._last_login_at = -RELOGIN_COOLDOWN_SECONDS

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
        """Nothing is rewritten -- a Vault path keeps `/`, `_` and `-`. What is
        rejected is anything but slash-joined runs of unreserved characters.

        A `.` or `..` segment escapes the mount, because requests strips dot
        segments client-side before the request leaves the process: measured,
        `../../auth/token/lookup-self` reaches `/v1/auth/token/lookup-self`. An
        empty segment aliases two names onto one secret. Every other character is
        inert only while hvac keeps percent-escaping it, which is a guarantee of
        its internals rather than of ours, so the allowlist stands on its own.
        """
        if not isinstance(secret_name, str):
            raise CloudSecretsError(
                f"Secret name must be a string, got {type(secret_name).__name__}"
            )
        segments = secret_name.split("/")
        legal = all(_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segments)
        if not legal:
            raise CloudSecretsError(
                f"Secret name '{secret_name}' is not a path under the mount"
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
            ) from None

        try:
            self.client.auth.kubernetes.login(
                role=self._role, jwt=jwt, mount_point=self._auth_mount_point
            )
        except Exception as e:
            raise ConfigurationError(
                f"Vault Kubernetes login for role '{self._role}' failed: "
                f"{type(e).__name__}"
            ) from None

    def _reauthenticate(self, seen_generation: int) -> bool:
        """Refresh the Vault token, and report whether the caller should retry.

        Retries without logging in when another caller has already refreshed
        since the failed call started -- at a TTL rollover every in-flight
        request is holding the same dead token, and only one of them needs to pay
        for a new one. Declines when a login was attempted inside
        RELOGIN_COOLDOWN_SECONDS, which is what keeps a denied path from becoming
        a login per read. The attempt is recorded before the login runs, so a
        login that fails is subject to the same floor and a transient failure
        cannot leave the client unable to authenticate again.
        """
        with self._auth_lock:
            if self._auth_generation != seen_generation:
                return True
            now = time.monotonic()
            if now - self._last_login_at < RELOGIN_COOLDOWN_SECONDS:
                return False
            self._last_login_at = now
            self._login()
            self._auth_generation += 1
            return True

    def _with_relogin(self, action: Callable[[], Any]) -> Any:
        """Run a Vault call, refreshing an expired token once and retrying.

        A Kubernetes-auth token has its own TTL and outlives neither the pod nor
        that TTL, so a client held for the life of a process has to be able to
        authenticate again. Vault answers a policy denial with the same 403, and
        the two are told apart by outcome rather than by inspection: a refresh is
        rate-limited, so a denial that survives it costs one login rather than
        one per read. A static token cannot be renewed, so it never retries.
        """
        generation = self._auth_generation
        try:
            return action()
        except (Forbidden, Unauthorized):
            if not self._role or not self._reauthenticate(generation):
                raise
        return action()

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
            ) from None
        except CloudSecretsError:
            raise
        except Exception as e:
            raise ConfigurationError(f"Error retrieving secret: {e}") from e

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
        except CloudSecretsError:
            raise
        except Exception as e:
            raise ConfigurationError(
                f"Failed to store secret '{secret_name}': {type(e).__name__}"
            ) from None

    def _delete_raw_secret(self, secret_name: str) -> None:
        def destroy():
            return self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=secret_name, mount_point=self.mount_point
            )

        try:
            self._with_relogin(destroy)
        except InvalidPath:
            pass
        except CloudSecretsError:
            raise
        except Exception as e:
            raise ConfigurationError(
                f"Failed to delete secret '{secret_name}': {e}"
            ) from e
