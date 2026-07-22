"""Runtime configuration pulled from the environment, with local-dev defaults."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    neo4j_uri: str = os.getenv("EYE_NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("EYE_NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("EYE_NEO4J_PASSWORD", "eye-dev-password")
    postgres_dsn: str = os.getenv(
        "EYE_POSTGRES_DSN", "postgresql://eye:eye@localhost:5432/eye"
    )
    # HMAC key used to sign/verify engagement scopes. Must be set in any real deployment.
    scope_signing_key: str = os.getenv("EYE_SCOPE_SIGNING_KEY", "dev-insecure-signing-key")
    # Root directory that uploaded SAST codebases are extracted into. It must resolve to the SAME
    # absolute path on the host, inside the api/worker containers, and inside any MCP SAST sibling
    # (e.g. the pooled Snyk container), so the extracted path a run targets means the same thing in
    # each place. In Compose that is a host bind mount at /eye-uploads; locally it is just a host dir.
    upload_root: str = os.getenv("EYE_UPLOAD_ROOT", "/eye-uploads")


settings = Settings()
