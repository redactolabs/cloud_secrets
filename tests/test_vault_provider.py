import json
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import environ
import pytest
from hvac.exceptions import Forbidden, InvalidPath, Unauthorized

from cloud_secrets import SecretManager
from cloud_secrets.common.exceptions import (
    CloudSecretsError,
    ConfigurationError,
    SecretNotFoundError,
)
from cloud_secrets.providers.vault_provider import (
    RELOGIN_COOLDOWN_SECONDS,
    SERVICE_ACCOUNT_TOKEN_PATH,
    VaultSecretsProvider,
    _from_fields,
    _to_fields,
)

VAULT_URL = "https://vault.internal:8200"

SA_JWT = "eyJhbGciOi.SERVICE-ACCOUNT-JWT-BODY.sig"


@pytest.fixture
def vault_client():
    """A patched hvac.Client, with environ isolated from the real process."""
    with (
        patch("cloud_secrets.providers.vault_provider.hvac.Client") as mock_cls,
        patch.object(environ.Env, "ENVIRON", {}),
    ):
        client = MagicMock()
        client.token = "static-token"
        mock_cls.return_value = client
        yield mock_cls, client


@pytest.fixture
def sa_token():
    """Kubernetes rotates the projected token, so _login re-reads it every time
    and the patch has to outlive construction.

    Path.read_text is a shared class attribute, so this asserts the path instead
    of answering every read in the process — otherwise an unrelated read during
    one of these tests would silently get a JWT instead of failing.
    """

    def read_text(self, *args, **kwargs):
        assert str(self) == SERVICE_ACCOUNT_TOKEN_PATH
        return SA_JWT

    with patch.object(Path, "read_text", read_text):
        yield


@pytest.fixture
def provider(vault_client):
    _, client = vault_client
    yield VaultSecretsProvider(url=VAULT_URL, token="static-token"), client


def build_provider(**kwargs: object) -> VaultSecretsProvider:
    kwargs.setdefault("url", VAULT_URL)
    kwargs.setdefault("token", "static-token")
    return VaultSecretsProvider(**kwargs)


def build_k8s_provider(**kwargs: object) -> VaultSecretsProvider:
    """A provider authenticated by role, so the re-login path is live. Needs the
    sa_token fixture: _login reads the token again on every re-login, not only at
    construction."""
    return VaultSecretsProvider(url=VAULT_URL, role="disco-python-pod", **kwargs)


def stored(client: MagicMock, fields: dict[str, object]):
    """Make the KV v2 read return `fields`, in Vault's nested response shape."""
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": fields, "metadata": {"version": 1}}
    }


def written_fields(client: MagicMock) -> dict[str, object]:
    return client.secrets.kv.v2.create_or_update_secret.call_args.kwargs["secret"]


class TestFieldMapping:
    """A KV v2 secret holds a field map; the library's API is a string."""

    def test_json_object_becomes_one_field_per_key(self):
        assert _to_fields('{"DB_HOST": "localhost", "PORT": "5432"}') == {
            "DB_HOST": "localhost",
            "PORT": "5432",
        }

    def test_non_json_value_goes_to_the_reserved_field(self):
        assert _to_fields("pg-password-4e1f9c") == {"__raw__": "pg-password-4e1f9c"}

    def test_json_scalar_goes_to_the_reserved_field(self):
        """A bare JSON scalar is not a field map, so it is not spread."""
        assert _to_fields("42") == {"__raw__": "42"}

    def test_json_keyword_keeps_its_source_spelling(self):
        """json.loads("true") is True, whose str() is "True" — a different value."""
        assert _to_fields("true") == {"__raw__": "true"}

    def test_oversized_integer_literal_is_not_a_parse_crash(self):
        """CPython caps int(str) at 4300 digits and json.loads raises a plain
        ValueError, not a JSONDecodeError, for a longer run of digits."""
        digits = "1" * 5000

        assert _to_fields(digits) == {"__raw__": digits}

    def test_object_using_the_reserved_key_is_stored_whole(self):
        """Spreading it would make it indistinguishable from a wrapped string."""
        source = '{"__raw__": "hello"}'

        assert _to_fields(source) == {"__raw__": source}

    @pytest.mark.parametrize(
        "source",
        [
            '{"access_key_id": "AKIA123", "secret": "abc/def+GHI=jkl"}',
            '{"__raw__": "hello"}',
            '{"__raw__": "a", "OTHER": "b"}',
            "postgres://u:p@h/db",
            "true",
            "42",
            "{}",
            "",
            '{"k": "caf\u00e9"}',
            '{"caf\u00e9": "v"}',
            '{"k": "\U0001f600"}',
        ],
        ids=[
            "json-object",
            "object-using-the-reserved-key",
            "reserved-key-among-others",
            "connection-string",
            "json-keyword",
            "json-number",
            "empty-object",
            "empty-string",
            "non-ascii-value",
            "non-ascii-key",
            "astral-plane",
        ],
    )
    def test_every_shape_round_trips(self, source):
        """The expected value is the input itself, never a second call to the
        code under test."""
        assert _from_fields(_to_fields(source)) == source

    def test_operator_written_fields_read_back_as_json(self):
        """`vault kv put secret/bundle DB_HOST=... PORT=...` is the intended way in."""
        assert json.loads(_from_fields({"DB_HOST": "localhost", "PORT": "5432"})) == {
            "DB_HOST": "localhost",
            "PORT": "5432",
        }

    def test_a_non_string_reserved_field_is_not_unwrapped(self):
        """Another writer can store a number there through the HTTP API, and the
        base class assigns whatever comes back to os.environ, which rejects a
        non-string with a TypeError."""
        assert json.loads(_from_fields({"__raw__": 42})) == {"__raw__": 42}

    def test_reserved_field_alongside_others_is_not_unwrapped(self):
        fields = {"__raw__": "a", "OTHER": "b"}

        assert json.loads(_from_fields(fields)) == fields


class TestSecretNames:
    """Vault paths are not Azure names: `/`, `_` and `-` are all legal."""

    def test_a_name_with_separators_is_passed_through_verbatim(self, provider):
        prov, client = provider
        stored(client, {"K": "v"})
        name = "disco/python_pod-env"

        prov.get_secret(name)

        assert client.secrets.kv.v2.read_secret_version.call_args.kwargs["path"] == name

    @pytest.mark.parametrize(
        "name",
        ["../../auth/token/lookup-self", "a/../../sys/policies/acl/admin", ".."],
        ids=["leading", "embedded", "bare"],
    )
    def test_a_dot_dot_segment_is_rejected(self, provider, name):
        """requests normalises `..` away client-side, so the mount stops scoping
        the request and any endpoint the token can reach becomes callable."""
        prov, client = provider

        with pytest.raises(CloudSecretsError, match="not a path under the mount"):
            prov.get_secret(name)

        client.secrets.kv.v2.read_secret_version.assert_not_called()

    def test_a_dot_dot_segment_cannot_reach_delete(self, provider):
        """The worst case: delete_metadata_and_all_versions is irreversible and
        InvalidPath is swallowed, so a sweep would leave no trace."""
        prov, client = provider

        with pytest.raises(CloudSecretsError):
            prov.delete_secret("../../sys/policies/acl/admin")

        client.secrets.kv.v2.delete_metadata_and_all_versions.assert_not_called()

    def test_a_dot_dot_segment_cannot_reach_write(self, provider):
        prov, client = provider

        with pytest.raises(CloudSecretsError):
            prov.set_secret("../../auth/token/create", '{"policies": ["root"]}')

        client.secrets.kv.v2.create_or_update_secret.assert_not_called()

    @pytest.mark.parametrize(
        "name",
        ["a//b", "/leading", "trailing/", ".", "a/./b", "a b", "a%2fb", "a\x00b"],
        ids=[
            "empty-segment",
            "leading-slash",
            "trailing-slash",
            "bare-dot",
            "dot-segment",
            "space",
            "percent",
            "nul",
        ],
    )
    def test_a_name_outside_the_allowlist_is_rejected(self, provider, name):
        """An empty or dot segment aliases or escapes; everything else is inert
        only while hvac keeps percent-escaping it, which is not our guarantee."""
        prov, client = provider

        with pytest.raises(CloudSecretsError):
            prov.get_secret(name)

        client.secrets.kv.v2.read_secret_version.assert_not_called()

    def test_a_non_string_name_raises_a_library_error(self, provider):
        """_canonical_name runs before the base class's try, so an AttributeError
        would escape a library that otherwise only raises CloudSecretsError."""
        prov, _client = provider

        with pytest.raises(CloudSecretsError, match="must be a string"):
            prov.get_secret(b"bytes-name")

    def test_a_dotted_name_that_does_not_escape_is_allowed(self, provider):
        """Only `..` walks out; a dot inside a segment is an ordinary character."""
        prov, client = provider
        stored(client, {"K": "v"})

        prov.get_secret("disco.api/v1.2-env")

        assert (
            client.secrets.kv.v2.read_secret_version.call_args.kwargs["path"]
            == "disco.api/v1.2-env"
        )


class TestVaultRead:
    def test_get_secret_returns_the_field_map_as_json(self, provider):
        prov, client = provider
        stored(client, {"DATABASE_URL": "postgres://x", "PREFETCH": "2"})

        result = prov.get_secret("disco-python-pod-env")

        assert json.loads(result) == {"DATABASE_URL": "postgres://x", "PREFETCH": "2"}

    def test_read_asks_for_the_configured_mount(self, vault_client):
        _, client = vault_client
        stored(client, {"K": "v"})
        prov = build_provider(mount_point="kv-disco")

        prov.get_secret("bundle")

        client.secrets.kv.v2.read_secret_version.assert_called_once_with(
            path="bundle", mount_point="kv-disco", raise_on_deleted_version=True
        )

    def test_missing_path_raises_secret_not_found(self, provider):
        prov, client = provider
        client.secrets.kv.v2.read_secret_version.side_effect = InvalidPath("nope")

        with pytest.raises(SecretNotFoundError):
            prov._fetch_raw_secret("absent")

        with pytest.raises(SecretNotFoundError):
            prov.get_secret("absent")

    def test_not_found_names_the_mount(self, vault_client):
        """Vault answers a mount that does not exist with the same 404 as a
        missing secret, so the message has to point at both."""
        _, client = vault_client
        client.secrets.kv.v2.read_secret_version.side_effect = InvalidPath("nope")
        prov = build_provider(mount_point="kv-typo")

        with pytest.raises(SecretNotFoundError, match="kv-typo"):
            prov._fetch_raw_secret("present-under-another-mount")

    def test_bundle_keys_never_reach_the_process_environment(self, provider):
        """The cloud providers destructure a fetched bundle into os.environ. This
        one must not: that is how a value ends up in a log line. The raw value is
        still written under the secret's own name, which the base class needs."""
        prov, client = provider
        marker = "pg-password-4e1f9c"
        stored(client, {"DATABASE_URL": f"postgres://u:{marker}@h/db"})

        prov.get_secret("disco-python-pod-env")

        env = prov.get_env().ENVIRON
        assert "DATABASE_URL" not in env
        assert set(env) == {"disco-python-pod-env"}


class TestVaultWrite:
    def test_set_secret_spreads_a_json_object_across_fields(self, provider):
        prov, client = provider

        prov.set_secret("bundle", '{"DB_HOST": "localhost", "PORT": "5432"}')

        assert written_fields(client) == {"DB_HOST": "localhost", "PORT": "5432"}

    def test_set_secret_wraps_a_plain_string(self, provider):
        prov, client = provider

        prov.set_secret("scalar", "plain-value")

        assert written_fields(client) == {"__raw__": "plain-value"}

    def test_delete_removes_every_version(self, provider):
        prov, client = provider

        prov.delete_secret("bundle")

        client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
            path="bundle", mount_point="secret"
        )

    def test_delete_surfaces_a_bad_mount_rather_than_reporting_success(
        self, vault_client
    ):
        """hvac documents this endpoint as 204-only, so a 404 is the mount, not a
        missing secret -- and the call destroys every version. Swallowing it told
        an erasure job that deletions succeeded while nothing was removed."""
        _, client = vault_client
        client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = InvalidPath(
            "no handler for route"
        )
        prov = build_provider(mount_point="kv-typo")

        with pytest.raises(ConfigurationError) as raised:
            prov.delete_secret("prod-db")

        assert "kv-typo" in str(raised.value)
        assert "prod-db" in str(raised.value)

    def test_delete_failure_is_wrapped(self, provider):
        prov, client = provider
        client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = (
            RuntimeError("boom")
        )

        with pytest.raises(ConfigurationError, match="Failed to delete secret"):
            prov.delete_secret("bundle")

    def test_delete_surfaces_a_login_failure_instead_of_re_redacting_it(
        self, vault_client, sa_token
    ):
        """The write path already does this; delete had the same re-wrap."""
        _, client = vault_client
        client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = Forbidden(
            "token expired"
        )
        prov = build_k8s_provider()
        client.auth.kubernetes.login.side_effect = RuntimeError("x509: unknown CA")

        with pytest.raises(ConfigurationError) as raised:
            prov.delete_secret("bundle")

        assert "disco-python-pod" in str(raised.value)
        assert not str(raised.value).startswith("Failed to delete")

    def test_store_failure_does_not_echo_the_exception(self, provider):
        """hvac stringifies a non-JSON error body verbatim, and the KV write's
        body is the secret. A gateway that quotes the request would put the
        secret in the error message."""
        prov, client = provider
        marker = "pg-password-4e1f9c"
        client.secrets.kv.v2.create_or_update_secret.side_effect = RuntimeError(
            f'upstream error: request was {{"data": {{"P": "{marker}"}}}}'
        )

        with pytest.raises(
            ConfigurationError, match="Failed to store secret"
        ) as raised:
            prov.set_secret("bundle", json.dumps({"P": marker}))

        assert marker not in str(raised.value)
        assert "RuntimeError" in str(raised.value)
        assert "bundle" in str(raised.value)
        assert raised.value.__suppress_context__

    def test_store_surfaces_a_login_failure_instead_of_re_redacting_it(
        self, vault_client, sa_token
    ):
        """_login already stripped the sensitive text, so wrapping its error
        again would leave a message naming neither the role nor the cause."""
        _, client = vault_client
        client.secrets.kv.v2.create_or_update_secret.side_effect = Forbidden("expired")
        prov = build_k8s_provider()
        client.auth.kubernetes.login.side_effect = RuntimeError("x509: unknown CA")

        with pytest.raises(ConfigurationError, match="login for role") as raised:
            prov.set_secret("bundle", '{"K": "v"}')

        assert "disco-python-pod" in str(raised.value)


class TestEditionCompatibility:
    """The edition a customer bought must never become a branch in our code."""

    def test_namespace_is_forwarded_when_given(self, vault_client):
        mock_cls, _ = vault_client

        build_provider(namespace="admin")

        assert mock_cls.call_args.kwargs["namespace"] == "admin"

    def test_no_namespace_is_sent_when_unset(self, vault_client):
        """A Community cluster rejects the namespace header; absent and empty
        are different requests."""
        mock_cls, _ = vault_client

        build_provider()

        assert mock_cls.call_args.kwargs["namespace"] is None

    def test_ca_bundle_is_forwarded(self, vault_client):
        mock_cls, _ = vault_client

        build_provider(verify="/etc/ssl/bank-ca.pem")

        assert mock_cls.call_args.kwargs["verify"] == "/etc/ssl/bank-ca.pem"

    def test_default_mount_matches_vaults_own_default(self, vault_client):
        _, client = vault_client
        stored(client, {"K": "v"})

        build_provider().get_secret("bundle")

        kwargs = client.secrets.kv.v2.read_secret_version.call_args.kwargs
        assert kwargs["mount_point"] == "secret"


class TestKubernetesAuth:
    def test_login_uses_the_service_account_token(self, vault_client, sa_token):
        _, client = vault_client

        build_k8s_provider()

        client.auth.kubernetes.login.assert_called_once_with(
            role="disco-python-pod", jwt=SA_JWT, mount_point="kubernetes"
        )

    def test_login_uses_a_non_default_auth_mount(self, vault_client, sa_token):
        _, client = vault_client

        build_k8s_provider(auth_mount_point="kubernetes/eks-prod")

        assert (
            client.auth.kubernetes.login.call_args.kwargs["mount_point"]
            == "kubernetes/eks-prod"
        )

    def test_missing_service_account_token_names_the_path(self, vault_client):
        with patch(
            "cloud_secrets.providers.vault_provider.Path.read_text",
            side_effect=OSError("no such file"),
        ):
            with pytest.raises(ConfigurationError, match=SERVICE_ACCOUNT_TOKEN_PATH):
                VaultSecretsProvider(url=VAULT_URL, role="disco-python-pod")

    def test_login_failure_does_not_echo_the_service_account_token(
        self, vault_client, sa_token
    ):
        """hvac renders a non-JSON error body into the exception string, and the
        login request body carries the JWT. A gateway that quotes the request
        would otherwise put a replayable credential into the logs."""
        _, client = vault_client
        client.auth.kubernetes.login.side_effect = RuntimeError(
            f'gateway error: request was {{"jwt": "{SA_JWT}"}}'
        )

        with pytest.raises(ConfigurationError, match="login for role") as raised:
            build_k8s_provider()

        assert SA_JWT not in str(raised.value)
        assert "RuntimeError" in str(raised.value)
        assert raised.value.__suppress_context__, (
            "without `from None` the chained hvac exception still renders in a "
            "traceback, putting the JWT back into any exc_info log line"
        )

    @pytest.mark.parametrize("denial", [Forbidden, Unauthorized], ids=["403", "401"])
    def test_expired_token_logs_in_again_and_retries(
        self, vault_client, sa_token, denial
    ):
        """A Kubernetes-auth token expires while the pod outlives it. Vault
        answers an expired token with 403 and hvac raises Unauthorized on a 401,
        so both have to trigger the re-login."""
        _, client = vault_client
        client.secrets.kv.v2.read_secret_version.side_effect = [
            denial("token expired"),
            {"data": {"data": {"K": "v"}, "metadata": {}}},
        ]

        prov = build_k8s_provider()
        result = prov.get_secret("bundle")

        assert json.loads(result) == {"K": "v"}
        assert client.auth.kubernetes.login.call_count == 2
        assert client.secrets.kv.v2.read_secret_version.call_count == 2

    def test_a_persistent_denial_costs_one_login_not_one_per_read(
        self, vault_client, sa_token
    ):
        """Vault returns 403 for a policy denial too. Re-authenticating on every
        denied read would make a narrowed policy a TokenReview storm against the
        Kubernetes API server."""
        _, client = vault_client
        client.secrets.kv.v2.read_secret_version.side_effect = Forbidden("denied")

        prov = build_k8s_provider()
        for _attempt in range(5):
            with pytest.raises(ConfigurationError):
                prov.get_secret("bundle")

        assert client.auth.kubernetes.login.call_count == 2

    def test_a_later_expiry_still_recovers_after_the_cooldown(
        self, vault_client, sa_token
    ):
        """The floor bounds the login rate; it must not cap the pod's lifetime."""
        _, client = vault_client
        client.secrets.kv.v2.read_secret_version.side_effect = Forbidden("denied")

        with patch("cloud_secrets.providers.vault_provider.time.monotonic") as clock:
            clock.return_value = 1000.0
            prov = build_k8s_provider()
            with pytest.raises(ConfigurationError):
                prov.get_secret("bundle")
            assert client.auth.kubernetes.login.call_count == 2

            clock.return_value = 1000.0 + RELOGIN_COOLDOWN_SECONDS + 1
            client.secrets.kv.v2.read_secret_version.side_effect = [
                Forbidden("expired"),
                {"data": {"data": {"K": "v"}, "metadata": {}}},
            ]

            assert json.loads(prov.get_secret("bundle")) == {"K": "v"}

        assert client.auth.kubernetes.login.call_count == 3

    def test_a_failed_relogin_does_not_disable_later_ones(self, vault_client, sa_token):
        """The attempt is recorded before the login runs, so a transient
        TokenReview outage must not leave the client unable to authenticate for
        the rest of the process's life."""
        _, client = vault_client
        client.secrets.kv.v2.read_secret_version.side_effect = Forbidden("expired")
        client.auth.kubernetes.login.side_effect = [None, RuntimeError("apiserver 503")]

        with patch("cloud_secrets.providers.vault_provider.time.monotonic") as clock:
            clock.return_value = 1000.0
            prov = build_k8s_provider()
            with pytest.raises(ConfigurationError):
                prov.get_secret("bundle")

            clock.return_value = 1000.0 + RELOGIN_COOLDOWN_SECONDS + 1
            client.auth.kubernetes.login.side_effect = None
            client.secrets.kv.v2.read_secret_version.side_effect = [
                Forbidden("expired"),
                {"data": {"data": {"K": "v"}, "metadata": {}}},
            ]

            assert json.loads(prov.get_secret("bundle")) == {"K": "v"}

    def test_a_failing_relogin_is_rate_limited_too(self, vault_client, sa_token):
        """A broken auth path — a revoked role, a bad CA bundle — must not become
        a login per read either. The attempt is recorded before the login runs,
        so a login that raises still spends the cooldown."""
        _, client = vault_client
        client.secrets.kv.v2.read_secret_version.side_effect = Forbidden("expired")
        prov = build_k8s_provider()
        client.auth.kubernetes.login.side_effect = RuntimeError("x509: unknown CA")
        logins_at_start = client.auth.kubernetes.login.call_count

        with patch(
            "cloud_secrets.providers.vault_provider.time.monotonic",
            return_value=1000.0,
        ):
            for _attempt in range(5):
                with pytest.raises(ConfigurationError):
                    prov.get_secret("bundle")

        assert client.auth.kubernetes.login.call_count - logins_at_start == 1

    def test_every_thread_recovers_from_one_shared_expiry(self, vault_client, sa_token):
        """SecretManager is shared across threads. At a TTL rollover every
        in-flight call holds the same dead token, so one login has to serve all
        of them rather than one winning and the rest failing."""
        _, client = vault_client
        live = threading.Event()
        ok = {"data": {"data": {"K": "v"}, "metadata": {}}}

        def read(**kwargs):
            if live.is_set():
                return ok
            raise Forbidden("token expired")

        def login(**kwargs):
            time.sleep(0.05)
            live.set()

        client.secrets.kv.v2.read_secret_version.side_effect = read
        prov = build_k8s_provider()
        client.auth.kubernetes.login.side_effect = login
        logins_at_start = client.auth.kubernetes.login.call_count

        results: list[str] = []
        errors: list[Exception] = []

        def call():
            try:
                results.append(prov.get_secret("bundle"))
            except Exception as e:  # noqa: BLE001 - recorded, then asserted on
                errors.append(e)

        threads = [threading.Thread(target=call) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(results) == 8
        assert client.auth.kubernetes.login.call_count - logins_at_start == 1

    def test_a_static_token_is_not_retried(self, provider):
        """A static token cannot be renewed, so retrying only doubles the latency."""
        prov, client = provider
        client.secrets.kv.v2.read_secret_version.side_effect = Forbidden("denied")

        with pytest.raises(ConfigurationError):
            prov.get_secret("bundle")

        assert client.secrets.kv.v2.read_secret_version.call_count == 1


class TestConfiguration:
    def test_missing_url_is_rejected(self, vault_client):
        with pytest.raises(ConfigurationError, match="url is required"):
            VaultSecretsProvider(token="t")

    def test_client_construction_failure_is_wrapped(self, vault_client):
        """__init__ promises ConfigurationError, so a raw hvac error must not
        escape to the caller."""
        mock_cls, _ = vault_client
        mock_cls.side_effect = RuntimeError("bad adapter")

        with pytest.raises(ConfigurationError, match="Failed to initialize"):
            build_provider()

    def test_neither_role_nor_token_is_rejected(self, vault_client):
        """An anonymous client would fail later, at the first read, with a 403."""
        _, client = vault_client
        client.token = None

        with pytest.raises(ConfigurationError, match="Kubernetes role or a token"):
            VaultSecretsProvider(url=VAULT_URL)

    def test_manager_resolves_the_vault_provider(self, vault_client):
        manager = SecretManager(provider_type="vault", url=VAULT_URL, token="t")

        assert isinstance(manager.provider, VaultSecretsProvider)
