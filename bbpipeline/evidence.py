from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from bbpipeline.models import Evidence, utcnow
from bbpipeline.redaction import redact
from bbpipeline.settings import Settings


SAFE_COMPONENT = re.compile(r"[^a-zA-Z0-9_.-]+")


def safe_component(value: str) -> str:
    cleaned = SAFE_COMPONENT.sub("_", value).strip("._")
    return cleaned[:120] or "item"


class EvidenceStore:
    def __init__(self, settings: Settings):
        self.root = settings.evidence_dir.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o750)

    def _absolute(self, relative_path: str) -> Path:
        candidate = (self.root / relative_path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError("evidence path escapes the evidence root")
        return candidate

    def write_bytes(
        self,
        session: Session,
        *,
        program_id: str,
        job_id: str | None,
        kind: str,
        filename: str,
        content: bytes,
        retention_days: int,
        media_type: str = "application/octet-stream",
        redacted: bool = True,
    ) -> Evidence:
        evidence = Evidence(
            program_id=program_id,
            job_id=job_id,
            kind=kind,
            relative_path="pending",
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            media_type=media_type,
            redacted=redacted,
            expires_at=utcnow() + timedelta(days=retention_days),
        )
        session.add(evidence)
        session.flush()

        relative = "/".join(
            [safe_component(program_id), evidence.id, safe_component(filename)]
        )
        destination = self._absolute(relative)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".evidence-", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        evidence.relative_path = relative
        session.flush()
        return evidence

    def write_json(
        self,
        session: Session,
        *,
        program_id: str,
        job_id: str | None,
        kind: str,
        filename: str,
        value: Any,
        retention_days: int,
        apply_redaction: bool = True,
    ) -> Evidence:
        output = redact(value) if apply_redaction else value
        content = json.dumps(output, sort_keys=True, ensure_ascii=False, indent=2).encode("utf-8")
        return self.write_bytes(
            session,
            program_id=program_id,
            job_id=job_id,
            kind=kind,
            filename=filename,
            content=content,
            retention_days=retention_days,
            media_type="application/json",
            redacted=apply_redaction,
        )

    def read_excerpt(self, evidence: Evidence, *, limit: int = 4096) -> str:
        if evidence.deleted_at is not None:
            return ""
        path = self._absolute(evidence.relative_path)
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")

    def purge_expired(self, session: Session) -> list[str]:
        now = utcnow()
        expired = session.scalars(
            select(Evidence).where(
                Evidence.expires_at < now,
                Evidence.hold.is_(False),
                Evidence.deleted_at.is_(None),
            )
        ).all()
        deleted: list[str] = []
        for evidence in expired:
            path = self._absolute(evidence.relative_path)
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue
            evidence.deleted_at = now
            deleted.append(evidence.id)
        session.flush()
        return deleted
