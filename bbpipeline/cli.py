from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import uvicorn
import yaml

from bbpipeline.adapters.nuclei import profile_hash
from bbpipeline.db import db_ready, init_db, session_scope
from bbpipeline.healthcheck import auth_mode, check_llm_provider
from bbpipeline.manifest import load_manifests, manifest_hash
from bbpipeline.platform_sources import (
    PlatformSourceConfig,
    discover_platform_programs,
    load_platform_sources,
)
from bbpipeline.platform_sync import (
    export_platform_candidate,
    platform_candidate_document,
    platform_source_summaries,
    sync_platform_sources,
)
from bbpipeline.programs import (
    approval_summary,
    invalid_manifest_summary,
    require_active_program,
    sync_programs,
)
from bbpipeline.queue import enqueue
from bbpipeline.redaction import redact_text
from bbpipeline.scheduler import scheduler_loop
from bbpipeline.settings import get_settings
from bbpipeline.workers import worker_loop


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _json(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bbpipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db")
    subparsers.add_parser("sync-programs")
    subparsers.add_parser("validate-config")
    subparsers.add_parser("doctor")

    discover_parser = subparsers.add_parser("platform-discover")
    discover_parser.add_argument(
        "--platform",
        required=True,
        choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"],
    )
    source_template_parser = subparsers.add_parser("platform-source-template")
    source_template_parser.add_argument("--platform", required=True)
    source_template_parser.add_argument("--remote", required=True)
    source_template_parser.add_argument("--program", required=True)
    source_template_parser.add_argument("--source")
    source_template_parser.add_argument(
        "--program-type", default="bug-bounty", choices=["bug-bounty", "vdp"]
    )
    sync_parser = subparsers.add_parser("platform-sync")
    sync_parser.add_argument("--source")
    subparsers.add_parser("platform-candidates")
    candidate_parser = subparsers.add_parser("platform-candidate")
    candidate_parser.add_argument("--source", required=True)
    export_parser = subparsers.add_parser("platform-export")
    export_parser.add_argument("--source", required=True)
    export_parser.add_argument("--output-dir", required=True, type=Path)

    manifest_parser = subparsers.add_parser("manifest-hash")
    manifest_parser.add_argument("path", type=Path)
    profile_parser = subparsers.add_parser("profile-hash")
    profile_parser.add_argument("path", type=Path)

    api_parser = subparsers.add_parser("api")
    api_parser.add_argument("--host", default="0.0.0.0")
    api_parser.add_argument("--port", default=8080, type=int)
    subparsers.add_parser("scheduler")

    worker_parser = subparsers.add_parser("worker")
    worker_parser.add_argument("--queues", default="scan")
    llm_parser = subparsers.add_parser("llm-worker")
    llm_parser.add_argument("--provider", required=True, choices=["codex", "claude"])
    llm_check_parser = subparsers.add_parser("llm-check")
    llm_check_parser.add_argument("--provider", required=True, choices=["codex", "claude"])

    enqueue_parser = subparsers.add_parser("enqueue")
    enqueue_parser.add_argument("--program", required=True)
    enqueue_parser.add_argument(
        "--kind", required=True, choices=["bbot", "nuclei", "github", "gitleaks", "shodan"]
    )
    enqueue_parser.add_argument("--payload", default="{}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)

    if args.command == "manifest-hash":
        raw = yaml.safe_load(args.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SystemExit("manifest must be a YAML mapping")
        print(manifest_hash(raw))
        return 0
    if args.command == "profile-hash":
        raw = yaml.safe_load(args.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SystemExit("profile must be a YAML mapping")
        print(profile_hash(raw))
        return 0
    if args.command == "platform-discover":
        _json(discover_platform_programs(settings, args.platform))
        return 0
    if args.command == "platform-source-template":
        source_id = args.source or f"{args.platform}-{args.program}"
        source = PlatformSourceConfig(
            version=1,
            source_id=source_id,
            program_id=args.program,
            platform=args.platform,
            remote_identifier=args.remote,
            program_type=args.program_type,
        )
        print(yaml.safe_dump(source.model_dump(mode="json"), sort_keys=False), end="")
        return 0
    if args.command == "validate-config":
        manifests = load_manifests(settings.program_dir)
        platform_sources = load_platform_sources(settings.platform_source_dir)
        sources_by_program = {
            source.program_id: source for source in platform_sources.loaded if source.enabled
        }
        source_bindings = []
        for entry in manifests.loaded:
            configured = sources_by_program.get(entry.manifest.program_id)
            if configured is None and entry.manifest.source is None:
                continue
            matches = bool(
                configured
                and entry.manifest.source
                and configured.source_id == entry.manifest.source.source_id
                and configured.platform == entry.manifest.source.platform
                and configured.remote_identifier == entry.manifest.source.remote_identifier
            )
            source_bindings.append(
                {
                    "program_id": entry.manifest.program_id,
                    "source_id": configured.source_id if configured else None,
                    "bound": matches,
                }
            )
        _json(
            {
                "programs": [approval_summary(entry) for entry in manifests.loaded],
                "invalid_manifests": [
                    invalid_manifest_summary(entry) for entry in manifests.invalid
                ],
                "platform_sources": [
                    {
                        "source_id": source.source_id,
                        "program_id": source.program_id,
                        "platform": source.platform,
                        "enabled": source.enabled,
                    }
                    for source in platform_sources.loaded
                ],
                "invalid_platform_sources": [
                    {
                        "source_id": item.source_id,
                        "path": str(item.path),
                        "error": item.error,
                    }
                    for item in platform_sources.invalid
                ],
                "source_bindings": source_bindings,
            }
        )
        approved = all(entry.approved for entry in manifests.loaded)
        bindings_valid = all(item["bound"] for item in source_bindings)
        return (
            0
            if approved
            and not manifests.invalid
            and not platform_sources.invalid
            and bindings_valid
            else 2
        )
    if args.command == "llm-check":
        # Deliberately runs before init_db so an operator can verify a worker's login
        # with `docker compose run --no-deps`, before the database is up.
        try:
            _json(check_llm_provider(settings, args.provider))
        except Exception as exc:  # noqa: BLE001 - report any failure as a check result
            _json(
                {
                    "provider": args.provider,
                    "auth_mode": auth_mode(settings, args.provider),
                    "authenticated": False,
                    "error": redact_text(f"{type(exc).__name__}: {exc}")[:1000],
                }
            )
            return 1
        return 0
    if args.command == "api":
        uvicorn.run(
            "bbpipeline.api:app",
            host=args.host,
            port=args.port,
            log_level=settings.log_level.lower(),
        )
        return 0

    init_db(settings)
    if args.command == "init-db":
        print("database initialized")
        return 0
    if args.command == "sync-programs":
        with session_scope(settings) as session:
            programs = sync_programs(session, settings, actor="cli")
            _json(
                [
                    {
                        "program_id": program.id,
                        "active": program.active,
                        "manifest_hash": program.manifest_hash,
                        "approved_hash": program.approved_hash,
                        "paused_reason": program.paused_reason,
                    }
                    for program in programs
                ]
            )
        return 0
    if args.command == "platform-sync":
        with session_scope(settings) as session:
            results = sync_platform_sources(session, settings, source_id=args.source)
            _json(results)
        return 1 if any(result.get("error") for result in results) else 0
    if args.command == "platform-candidates":
        with session_scope(settings) as session:
            _json(platform_source_summaries(session))
        return 0
    if args.command == "platform-candidate":
        with session_scope(settings) as session:
            _json(platform_candidate_document(session, args.source))
        return 0
    if args.command == "platform-export":
        with session_scope(settings) as session:
            _json(export_platform_candidate(session, args.source, args.output_dir))
        return 0
    if args.command == "doctor":
        manifests = load_manifests(settings.program_dir)
        platform_sources = load_platform_sources(settings.platform_source_dir)
        result = {
            "database_ready": db_ready(settings),
            "programs": [approval_summary(entry) for entry in manifests.loaded],
            "invalid_manifests": [
                invalid_manifest_summary(entry) for entry in manifests.invalid
            ],
            "evidence_dir": str(settings.evidence_dir),
            "api_token_configured": bool(settings.read_secret(settings.api_token_file)),
            "discord_configured": bool(settings.read_secret(settings.discord_webhook_file)),
            "github_configured": bool(settings.read_secret(settings.github_token_file)),
            "shodan_configured": bool(settings.read_secret(settings.shodan_api_key_file)),
            "platform_sources": {
                "configured": len(platform_sources.loaded),
                "invalid": [
                    {
                        "source_id": item.source_id,
                        "path": str(item.path),
                        "error": item.error,
                    }
                    for item in platform_sources.invalid
                ],
                "hackerone_credential": bool(
                    settings.read_secret(settings.hackerone_api_token_file)
                ),
                "intigriti_credential": bool(
                    settings.read_secret(settings.intigriti_api_token_file)
                ),
                "yeswehack_credential": bool(
                    settings.read_secret(settings.yeswehack_access_token_file)
                ),
                "bugcrowd_cookie": bool(
                    settings.read_secret(settings.bugcrowd_session_cookie_file)
                ),
            },
        }
        _json(result)
        return 0 if result["database_ready"] else 1
    if args.command == "scheduler":
        scheduler_loop(settings)
        return 0
    if args.command == "worker":
        queues = [queue.strip() for queue in args.queues.split(",") if queue.strip()]
        worker_loop(settings, queues=queues)
        return 0
    if args.command == "llm-worker":
        worker_loop(settings, queues=[f"llm-{args.provider}"], provider=args.provider)
        return 0
    if args.command == "enqueue":
        payload = json.loads(args.payload)
        if not isinstance(payload, dict):
            raise SystemExit("--payload must be a JSON object")
        with session_scope(settings) as session:
            require_active_program(session, args.program)
            job = enqueue(
                session,
                queue="scan",
                kind=args.kind,
                program_id=args.program,
                payload=payload,
                priority=20,
            )
            _json({"job_id": job.id, "status": job.status})
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
