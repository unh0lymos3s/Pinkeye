"""Runtime configuration pulled from the environment, with local-dev defaults.

S6: the dev defaults here are convenient and dangerous — `_signature_valid` is the only thing between
a `Scope` object and authorization, so anyone who knows the default signing key can forge a scope with
arbitrary CIDRs and both offensive flags. Anything but `EYE_ENV=development` therefore refuses to
start on a default secret rather than serving with one.
"""
import os
from dataclasses import dataclass

DEV_SIGNING_KEY = "dev-insecure-signing-key"


@dataclass(frozen=True)
class Settings:
    # Deployment environment. "development" (the default, so the single-host dev stack and the tests
    # keep working untouched) permits insecure defaults; every other value forbids them.
    env: str = os.getenv("EYE_ENV", "development")
    neo4j_uri: str = os.getenv("EYE_NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("EYE_NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("EYE_NEO4J_PASSWORD", "eye-dev-password")
    postgres_dsn: str = os.getenv(
        "EYE_POSTGRES_DSN", "postgresql://eye:eye@localhost:5432/eye"
    )
    # HMAC key used to sign/verify engagement scopes. Must be set in any real deployment.
    scope_signing_key: str = os.getenv("EYE_SCOPE_SIGNING_KEY", DEV_SIGNING_KEY)
    # Root directory that uploaded SAST codebases are extracted into. It must resolve to the SAME
    # absolute path on the host, inside the api/worker containers, and inside any MCP SAST sibling
    # (e.g. the pooled Snyk container), so the extracted path a run targets means the same thing in
    # each place. In Compose that is a host bind mount at /eye-uploads; locally it is just a host dir.
    upload_root: str = os.getenv("EYE_UPLOAD_ROOT", "/eye-uploads")


settings = Settings()


def is_development() -> bool:
    return settings.env.strip().lower() == "development"


def assert_secure_scope_key() -> None:
    """Refuse to run on the shipped signing key outside development.

    Enforced at import so it fires for every entrypoint that touches configuration (the API, the
    worker, any script), before a single request is served — a forged scope authorizes real traffic,
    so this must fail closed rather than warn.
    """
    if settings.scope_signing_key == DEV_SIGNING_KEY and not is_development():
        raise RuntimeError(
            "EYE_SCOPE_SIGNING_KEY is still the shipped development key. Set it to a real secret, "
            f"or set EYE_ENV=development to acknowledge an insecure dev stack (EYE_ENV={settings.env!r})."
        )


def assert_secure_authentication(open_dev_mode: bool) -> None:
    """Refuse to serve with the open dev-mode authenticator outside development.

    With no EYE_API_KEYS configured, `Authenticator.principal_for` returns a default-tenant *admin*
    for every request, which makes the API's RBAC decorative. Called from the API's startup hook,
    where the authenticator exists.
    """
    if open_dev_mode and not is_development():
        raise RuntimeError(
            "EYE_API_KEYS is unset, so every request would be authenticated as a default-tenant "
            f"admin. Configure API keys, or set EYE_ENV=development (EYE_ENV={settings.env!r})."
        )


assert_secure_scope_key()
