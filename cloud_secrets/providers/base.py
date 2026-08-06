"""Base provider implementation.

Two operations live here:

``get_secret`` reads a value and returns it, casting from the raw string rather
than round-tripping through the environment. Structured (JSON) secrets are
never parsed as dotenv, so a per-tenant credential cannot be fed through
``environ.read_env`` — which logs every unparseable line verbatim, and was
writing customer credentials to Cloud Logging one field at a time.

``load_secret_into_env`` is the explicit bootstrap path: fetch a service's own
settings blob and inject it into the environment. New code should use it; the
implicit injection still performed by the providers for dotenv-shaped blobs is
retained for compatibility and will be removed in 2.0.
"""

import json
import re

import environ
from abc import ABC, abstractmethod
from io import StringIO
from typing import Any, Dict, List, Optional, Mapping, Pattern

from environ import Env

from cloud_secrets.common.exceptions import CloudSecretsError, SecretNotFoundError

_ASSIGNMENT_LINE = re.compile(r"\A(?:export )?[A-Za-z_][A-Za-z_0-9]*=")


def _is_settings_blob(value: str) -> bool:
    """Whether a secret is a service's dotenv settings blob.

    Positive detection, because anything else must not be parsed: read_env
    logs each line it cannot parse, so a secret that merely *isn't* a settings
    blob would be written to the log verbatim.

    Excluded, deliberately:

    * JSON — per-tenant credential bundles (``org-sms-*``, ``org-ocr-*``).
    * Single-line scalars — an API token, or a connection string whose
      ``Key=Value;`` pairs would otherwise be split into bogus env keys.

    Requiring two assignments rather than *all* lines being assignments means a
    blob with a multi-line value (a PEM in ``GCP_SA_PRIVATE_KEY``) still counts
    as settings, where a stricter rule would reject it and break boot.
    """
    try:
        json.loads(value)
        return False
    except (ValueError, TypeError):
        pass

    assignments = sum(
        1 for line in value.splitlines() if _ASSIGNMENT_LINE.match(line)
    )
    return assignments >= 2


_CASTS: Mapping[str, Any] = {
    "str": str,
    "bool": bool,
    "int": int,
    "float": float,
    "list": list,
    "dict": dict,
}


class BaseSecretProvider(ABC):
    """Base class for secret providers with environ support."""

    _INVALID_NAME_CHARS: Pattern | None = None

    def __init__(self, env_path: Optional[str] = None, **kwargs):
        """Initialize the base provider with environ."""
        self.env = environ.Env()
        self.env_path = env_path

    def _canonical_name(self, secret_name: str) -> str:
        if self._INVALID_NAME_CHARS is None:
            return secret_name
        normalized = secret_name.replace("_", "-")
        if self._INVALID_NAME_CHARS.search(normalized):
            raise CloudSecretsError(
                f"Secret name '{secret_name}' has characters invalid for this provider"
            )
        return normalized

    @abstractmethod
    def _fetch_raw_secret(self, secret_name: str) -> str:
        """Return the raw secret value.

        A JSON value must be returned untouched — never parsed as dotenv and
        never logged. Providers may still inject a dotenv-shaped blob for
        compatibility with boot paths that rely on it; that behaviour is
        deprecated in favour of ``load_secret_into_env``.
        """

    @abstractmethod
    def _store_raw_secret(self, secret_name: str, secret_value: str) -> None:
        """Store or update a secret value in the provider backend."""

    @abstractmethod
    def _delete_raw_secret(self, secret_name: str) -> None:
        """Delete a secret from the provider backend. No-op if not found."""

    def set_secret(self, secret_name: str, secret_value: str) -> None:
        """Create or update a secret."""
        secret_name = self._canonical_name(secret_name)
        self._store_raw_secret(secret_name, secret_value)

    def delete_secret(self, secret_name: str) -> None:
        """Delete a secret. No-op if it doesn't exist."""
        secret_name = self._canonical_name(secret_name)
        self._delete_raw_secret(secret_name)
        self.env.ENVIRON.pop(secret_name, None)

    def get_env(self) -> Env:
        return self.env

    def load_secret_into_env(self, secret_name: str) -> Env:
        """Fetch a dotenv-formatted settings blob and inject it into the env.

        The bootstrap path, for a service loading its own configuration. Only
        call this for a blob you control; never for a per-tenant secret, whose
        contents would be parsed and could overwrite real settings.
        """
        secret_name = self._canonical_name(secret_name)

        try:
            value = self._fetch_raw_secret(secret_name)
        except CloudSecretsError:
            raise
        except Exception as e:
            raise SecretNotFoundError(f"Error retrieving secret {secret_name}: {e}")

        # overwrite=False: a settings blob supplies defaults, it does not get to
        # clobber values already deliberately set in the process environment.
        self.env.read_env(StringIO(value), overwrite=False)
        return self.env

    def get_secret(
        self,
        secret_name: str,
        cast_type: str = "str",
        dict_fields: Optional[Mapping[str, Any]] = None,
        **kwargs,
    ) -> Any:
        """Return a secret's value, cast as requested.

        Reads and returns only. The value is never written to ``os.environ``
        and never passed through a dotenv parser, so a JSON credential cannot
        leak into logs or the environment.
        """
        secret_name = self._canonical_name(secret_name)

        try:
            raw = self._fetch_raw_secret(secret_name)
        except CloudSecretsError:
            raise
        except Exception as e:
            raise SecretNotFoundError(f"Error retrieving secret {secret_name}: {e}")

        return self._cast(raw, cast_type=cast_type, dict_fields=dict_fields)

    @staticmethod
    def _cast(
        raw: str,
        cast_type: str = "str",
        dict_fields: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        if cast_type == "str":
            return raw

        if cast_type == "dict" and dict_fields:
            return Env.parse_value(raw, dict(value=str, cast=dict_fields))

        cast = _CASTS.get(cast_type)

        if cast is None:
            raise CloudSecretsError(f"Unsupported cast type: {cast_type}")

        return Env.parse_value(raw, cast)

    def get_dict(
        self, secret_name: str, field_types: Optional[Mapping[str, Any]] = None
    ) -> Dict:
        """Get secret as dictionary with optional field type casting."""
        return self.get_secret(secret_name, cast_type="dict", dict_fields=field_types)

    def get_list(self, secret_name: str) -> List:
        """Get secret as list."""
        return self.get_secret(secret_name, cast_type="list")

    def get_bool(self, secret_name: str) -> bool:
        """Get secret as boolean."""
        return self.get_secret(secret_name, cast_type="bool")

    def get_int(self, secret_name: str) -> int:
        """Get secret as integer."""
        return self.get_secret(secret_name, cast_type="int")

    def get_float(self, secret_name: str) -> float:
        """Get secret as float."""
        return self.get_secret(secret_name, cast_type="float")
