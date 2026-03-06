"""Finding fingerprint trend index with optional file-backed persistence."""

from __future__ import annotations

import json
import asyncio
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nocturna_engine.models.finding import Finding

_INDEX_SCHEMA_VERSION = "1"

def _atomic_replace(src: Path, dst: Path, retries: int = 3, delay: float = 0.1) -> None:
    """Replace *dst* with *src*, retrying on Windows lock conflicts."""
    for attempt in range(retries):
        try:
            src.replace(dst)
            return
        except OSError:
            if attempt == retries - 1:
                raise
            time.sleep(delay * (attempt + 1))


def _normalize_observed_at(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@dataclass(slots=True)
class FingerprintTrendEntry:
    """Lifecycle counters for one finding fingerprint."""

    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
        }


class FindingFingerprintIndex:
    """Store trend counters for deduplicated finding fingerprints."""

    def __init__(self, *, storage_path: str | Path | None = None) -> None:
        self._storage_path: Path | None = None
        self._entries: dict[str, FingerprintTrendEntry] = {}
        self._lock = asyncio.Lock()
        if storage_path is not None:
            self.configure_storage(storage_path)

    def configure_storage(self, storage_path: str | Path | None) -> None:
        if storage_path is None:
            self._storage_path = None
            return
        path = Path(storage_path).expanduser()
        self._storage_path = path
        self.load()

    def load(self) -> None:
        path = self._storage_path
        if path is None or not path.exists():
            return
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries_payload = payload.get("entries", {})
        if not isinstance(entries_payload, dict):
            return

        loaded: dict[str, FingerprintTrendEntry] = {}
        for fingerprint, raw_entry in entries_payload.items():
            if not isinstance(fingerprint, str) or not fingerprint.strip():
                continue
            if not isinstance(raw_entry, dict):
                continue
            first_seen = _parse_iso_datetime(raw_entry.get("first_seen"))
            last_seen = _parse_iso_datetime(raw_entry.get("last_seen"))
            count = raw_entry.get("count")
            if first_seen is None or last_seen is None:
                continue
            if not isinstance(count, int) or count < 0:
                continue
            loaded[fingerprint] = FingerprintTrendEntry(
                fingerprint=fingerprint,
                first_seen=first_seen,
                last_seen=last_seen,
                count=count,
            )
        self._entries = loaded

    def _persist_sync(self, snapshot: dict[str, FingerprintTrendEntry]) -> None:
        """Synchronous persist — intended to run in an executor."""
        path = self._storage_path
        if path is None:
            return
        payload = {
            "schema_version": _INDEX_SCHEMA_VERSION,
            "entries": {
                fingerprint: snapshot[fingerprint].to_dict()
                for fingerprint in sorted(snapshot)
            },
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(f"{path.suffix}.tmp")
        tmp_path.write_text(
            json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")),
            encoding="utf-8",
        )
        _atomic_replace(tmp_path, path)

    def persist(self) -> None:
        self._persist_sync(dict(self._entries))

    def observe_findings(
        self,
        findings: list[Finding],
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, FingerprintTrendEntry]:
        observed_fingerprints = {
            str(finding.fingerprint).strip()
            for finding in findings
            if str(finding.fingerprint).strip()
        }
        return self.observe_fingerprints(observed_fingerprints, observed_at=observed_at)

    def observe_fingerprints(
        self,
        fingerprints: set[str] | list[str] | tuple[str, ...],
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, FingerprintTrendEntry]:
        timestamp = _normalize_observed_at(observed_at)
        for fingerprint in sorted({item.strip() for item in fingerprints if item and item.strip()}):
            entry = self._entries.get(fingerprint)
            if entry is None:
                self._entries[fingerprint] = FingerprintTrendEntry(
                    fingerprint=fingerprint,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    count=1,
                )
                continue
            entry.last_seen = timestamp
            entry.count += 1
        self.persist()
        return {key: value for key, value in self._entries.items()}

    def get(self, fingerprint: str) -> FingerprintTrendEntry | None:
        return self._entries.get(fingerprint)

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            fingerprint: self._entries[fingerprint].to_dict()
            for fingerprint in sorted(self._entries)
        }

    def __len__(self) -> int:
        return len(self._entries)
