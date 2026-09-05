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

# A policy denial and an expired token share a 403, so only the denial is rate-limited.
RELOGIN_COOLDOWN_SECONDS = 30.0

_RAW_FIELD = "__raw__"

_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")


class VaultSecretsProvider(BaseSecretProvider):
    """HashiCorp Vault and OpenBao KV v2 provider.

    Neither `role` nor a token is a configuration error, not an anonymous client.

    A fetched secret's keys are never spread into the environment, but the raw
    value is still written under the secret's own name because the base class
    reads it back from there, and `environ.Env.ENVIRON` is `os.environ` -- a
    caller needing it out of the environment must pop that key itself.
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
                # requests forwards X-Vault-Token to the new host and replays the
                # login body on a 307, so a standby redirect would hand another
                # host the pod's credentials.
                allow_redirects=False,
            )
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize Vault client: {e}")

        self._login()

    def _canonical_name(self, secret_name: str) -> str:
        """Accepts only slash-joined runs of unreserved characters.

        requests strips dot segments client-side, so a `..` would send
        `{mount}/data/../../auth/token/lookup-self` to `/v1/auth/token/...`. An
        empty segment aliases two names onto one secret.
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

    def _login(self):
        """Re-reads the service account token from disk every time: Kubernetes
        rotates it, so a cached copy expires with the projected volume."""
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
        """Whether the caller should retry. True without logging in when another
        caller already refreshed since the failed call began, so one login serves
        every request in flight at a rollover. The attempt is recorded before the
        login runs, so a failing auth path cannot escape the floor or strand the
        client."""
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
        """Refreshes an expired token once and retries. A static token cannot be
        renewed, so it never retries."""
        generation = self._auth_generation
        try:
            return _reject_redirect(action())
        except (Forbidden, Unauthorized):
            if not self._role or not self._reauthenticate(generation):
                raise
        return action()

    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Raises SecretNotFoundError when the path holds no secret. A missing
        mount answers with the same 404, so the message names it too."""

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
        except CloudSecretsError:
            raise
        except Exception as e:
            raise ConfigurationError(
                f"Failed to delete secret '{secret_name}' under mount "
                f"'{self.mount_point}': {e}"
            ) from e


def _to_fields(secret_value: str) -> dict[str, Any]:
    """A JSON object spreads across Vault fields; anything else round-trips whole
    through the reserved field. An object already using that key is not spread --
    it would be indistinguishable from a wrapped string."""
    try:
        parsed = json.loads(secret_value)
    except ValueError:
        return {_RAW_FIELD: secret_value}
    if isinstance(parsed, dict) and _RAW_FIELD not in parsed:
        return parsed
    return {_RAW_FIELD: secret_value}


def _from_fields(fields: dict[str, Any]) -> str:
    """Recovers an equivalent JSON document, not the source text: spacing is lost
    and a field another writer stored as a number stays a number."""
    if list(fields) == [_RAW_FIELD] and isinstance(fields[_RAW_FIELD], str):
        return fields[_RAW_FIELD]
    return json.dumps(fields, ensure_ascii=False)


def _reject_redirect(result: Any) -> Any:
    """hvac parses JSON only on a 200 and raises only above 400, so a redirect it
    was told not to follow comes back as a plain Response that reads as success --
    a write would report having stored a secret it never sent."""
    status = getattr(result, "status_code", None)
    if isinstance(status, int) and 300 <= status < 400:
        raise ConfigurationError(
            f"vault redirected the request ({status}); redirects are not followed, "
            "point at the active node or a load balancer"
        )
    return result
