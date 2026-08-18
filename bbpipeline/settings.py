from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import quote_plus

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BB_",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str | None = None
    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "bbpipeline"
    db_user: str = "bbpipeline"
    db_password_file: Path = Path("/run/secrets/postgres_password")

    config_dir: Path = Path("/config")
    program_dir: Path = Path("/config/programs")
    platform_source_dir: Path = Path("/config/platform-sources")
    nuclei_profile_dir: Path = Path("/config/nuclei/profiles")
    evidence_dir: Path = Path("/data/evidence")
    ttp_dir: Path = Path("/app/methodology/ttp_cards")
    skill_dir: Path = Path("/app/skills/bug-bounty-review")
    schema_dir: Path = Path("/app/schemas")

    api_token_file: Path = Path("/run/secrets/api_token")
    discord_webhook_file: Path = Path("/run/secrets/discord_webhook")
    github_token_file: Path = Path("/run/secrets/github_token")
    shodan_api_key_file: Path = Path("/run/secrets/shodan_api_key")
    researcher_headers_file: Path = Path("/run/secrets/researcher_headers.json")
    hackerone_api_token_file: Path = Path("/run/secrets/hackerone_api_token")
    intigriti_api_token_file: Path = Path("/run/secrets/intigriti_api_token")
    yeswehack_access_token_file: Path = Path("/run/secrets/yeswehack_access_token")
    bugcrowd_session_cookie_file: Path = Path(
        "/run/secrets/bugcrowd_session_cookie"
    )

    # Optional metered-API credentials. When one is present its worker switches from
    # the subscription OAuth session to key authentication, which allows a stricter
    # sandbox. Empty or absent means "use the CLI's stored subscription login".
    anthropic_api_key_file: Path = Path("/run/secrets/anthropic_api_key")
    openai_api_key_file: Path = Path("/run/secrets/openai_api_key")

    log_level: str = "INFO"
    worker_poll_seconds: float = Field(default=5.0, ge=0.25, le=300)
    scheduler_poll_seconds: float = Field(default=30.0, ge=5, le=3600)
    job_lease_seconds: int = Field(default=7200, ge=60, le=86400)
    default_retention_days: int = Field(default=30, ge=1, le=3650)
    # The floor must leave room for the triage skill core plus one event. Below it,
    # every planner and critic packet would exceed the ceiling and fail at job time.
    max_context_bytes: int = Field(default=32768, ge=16384, le=131072)
    command_timeout_seconds: int = Field(default=3600, ge=30, le=86400)
    platform_http_timeout_seconds: int = Field(default=30, ge=5, le=120)
    platform_sync_seconds: int = Field(default=21600, ge=900, le=604800)
    platform_source_max_stale_seconds: int = Field(
        default=86400, ge=3600, le=2592000
    )
    researcher_handle: str = "d4kshn"
    bbscope_cookie_command: str = "bbscope-cookie"
    worker_id: str = "worker"
    codex_model: str = ""
    claude_model: str = ""

    @staticmethod
    def read_secret(path: Path, *, required: bool = False) -> str:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            if required:
                raise RuntimeError(f"Required secret file is missing: {path}") from None
            return ""
        if required and not value:
            raise RuntimeError(f"Required secret file is empty: {path}")
        return value

    @property
    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        password = quote_plus(self.read_secret(self.db_password_file, required=True))
        user = quote_plus(self.db_user)
        name = quote_plus(self.db_name)
        return f"postgresql+psycopg://{user}:{password}@{self.db_host}:{self.db_port}/{name}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
