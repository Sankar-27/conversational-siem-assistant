"""Document loader for MITRE, playbooks, and IR procedures."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from app.core.config import settings


@dataclass
class KnowledgeDocument:
    doc_id: str
    title: str
    content: str
    source: str
    doc_type: str  # mitre | playbook | ir_procedure | detection_rule
    metadata: dict


def _project_data_dir() -> Path:
    backend_dir = Path(__file__).resolve().parents[3]
    project_root = backend_dir.parent
    return project_root / "data"


def load_json_documents(path: Path, doc_type: str, source: str) -> Iterator[KnowledgeDocument]:
    if not path.exists():
        return
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        for item in data:
            yield KnowledgeDocument(
                doc_id=item.get("id", item.get("technique_id", str(hash(str(item))))),
                title=item.get("name", item.get("title", item.get("technique_name", "Untitled"))),
                content=item.get("description", item.get("content", json.dumps(item))),
                source=source,
                doc_type=doc_type,
                metadata={k: v for k, v in item.items() if k not in ("description", "content")},
            )


def load_markdown_documents(path: Path, doc_type: str, source: str) -> Iterator[KnowledgeDocument]:
    if not path.exists():
        return
    for md_file in path.glob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        yield KnowledgeDocument(
            doc_id=md_file.stem,
            title=md_file.stem.replace("_", " ").title(),
            content=content,
            source=source,
            doc_type=doc_type,
            metadata={"filename": md_file.name},
        )


def load_all_knowledge_documents() -> list[KnowledgeDocument]:
    data_dir = _project_data_dir()
    docs: list[KnowledgeDocument] = []

    mitre_path = data_dir / "mitre" / "techniques.json"
    docs.extend(load_json_documents(mitre_path, "mitre", "MITRE ATT&CK"))

    playbooks_dir = data_dir / "playbooks"
    if playbooks_dir.exists():
        for pb in playbooks_dir.glob("*.json"):
            docs.extend(load_json_documents(pb, "playbook", pb.stem))
        docs.extend(load_markdown_documents(playbooks_dir, "ir_procedure", "Incident Response"))

    rules_dir = data_dir / "detection_rules"
    docs.extend(load_json_documents(rules_dir / "rules.json", "detection_rule", "Detection Rules"))

    return docs
