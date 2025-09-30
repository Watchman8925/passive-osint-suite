from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Optional

DEFAULT_DIR = os.path.join(os.getcwd(), "output", "evidence")


@dataclass
class EvidenceRecord:
    evidence_id: str
    investigation_id: Optional[str]
    capability_id: Optional[str]
    artifact_type: str  # e.g., 'html','json','text','certificate','raw'
    created_at: float
    sha256: str
    size: int
    mime_type: Optional[str]
    source: Optional[str]
    tags: Dict[str, Any]
    # path relative to base evidence directory
    rel_path: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


class EvidenceStore:
    def __init__(self, base_dir: str = DEFAULT_DIR):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def _write_file(self, rel_path: str, data: bytes) -> None:
        abs_path = os.path.join(self.base_dir, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "wb") as f:
            f.write(data)

    def _write_meta(self, record: EvidenceRecord) -> None:
        meta_path = os.path.join(self.base_dir, f"{record.evidence_id}.meta.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            f.write(record.to_json())

    def save(
        self,
        data: bytes | str,
        *,
        investigation_id: Optional[str],
        capability_id: Optional[str],
        artifact_type: str,
        mime_type: Optional[str] = None,
        source: Optional[str] = None,
        tags: Optional[Dict[str, Any]] = None,
        suggested_name: Optional[str] = None,
    ) -> EvidenceRecord:
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data
        sha256 = hashlib.sha256(data_bytes).hexdigest()
        evidence_id = str(uuid.uuid4())
        subdir = sha256[:2]
        filename = suggested_name or f"{evidence_id}.blob"
        rel_path = os.path.join(subdir, filename)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            capability_id=capability_id,
            artifact_type=artifact_type,
            created_at=time.time(),
            sha256=sha256,
            size=len(data_bytes),
            mime_type=mime_type,
            source=source,
            tags=tags or {},
            rel_path=rel_path,
        )
        self._write_file(rel_path, data_bytes)
        self._write_meta(record)
        return record

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        meta_path = os.path.join(self.base_dir, f"{evidence_id}.meta.json")
        if not os.path.exists(meta_path):
            return None
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return EvidenceRecord(**data)

    def open_blob(self, record: EvidenceRecord) -> bytes:
        abs_path = os.path.join(self.base_dir, record.rel_path)
        with open(abs_path, "rb") as f:
            return f.read()

    def iter_records(self) -> Iterable[EvidenceRecord]:
        for name in os.listdir(self.base_dir):
            if name.endswith(".meta.json"):
                with open(
                    os.path.join(self.base_dir, name), "r", encoding="utf-8"
                ) as f:
                    data = json.load(f)
                yield EvidenceRecord(**data)


_default_store: Optional[EvidenceStore] = None


def get_default_store() -> EvidenceStore:
    global _default_store
    if _default_store is None:
        _default_store = EvidenceStore()
    return _default_store
