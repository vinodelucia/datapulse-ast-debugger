import datetime
import hashlib
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
import requests
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings
from pydantic import BaseModel, Field

from src.privacy import redact_sensitive, sanitize_category, sanitize_summary

MAX_EMBED_CHARS = 2000  # trunca o texto embutido (custo de embedding e ruído)

_ST_FN_CACHE: Dict[str, Any] = {}


def _get_sentence_transformer_fn() -> Optional[Any]:
    """Carrega o modelo all-MiniLM-L6-v2 uma única vez por processo (None se indisponível)."""
    if "fn" not in _ST_FN_CACHE:
        try:
            from chromadb.utils import embedding_functions

            _ST_FN_CACHE["fn"] = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
        except Exception:
            _ST_FN_CACHE["fn"] = None
    return _ST_FN_CACHE["fn"]


class DeterministicHashEmbeddingFunction(EmbeddingFunction[Documents]):
    """Fallback de embedding local determinístico (384 dimensões) caso o modelo HF não esteja em cache."""

    def __init__(self) -> None:
        pass

    @staticmethod
    def name() -> str:
        return "deterministic_hash_384"

    def get_config(self) -> Dict[str, Any]:
        return {}

    @staticmethod
    def build_from_config(config: Dict[str, Any]) -> "DeterministicHashEmbeddingFunction":
        return DeterministicHashEmbeddingFunction()

    def __call__(self, input: Documents) -> Embeddings:
        embeddings: Embeddings = []
        for doc in input:
            vec: List[float] = []
            seed = doc.encode("utf-8", errors="ignore")
            for i in range(12):
                digest = hashlib.sha256(seed + i.to_bytes(2, "little")).digest()
                for b in digest:
                    vec.append((b / 127.5) - 1.0)
            embeddings.append(vec[:384])
        return embeddings


class DiagnosticRecord(BaseModel):
    """Schema validado de cada diagnóstico gerado pelo agente."""

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str
    language: str
    access_point_id: str
    node_type: str = "function_definition"
    ast_hash: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    error_category: str
    diagnostic_summary: str
    original_code: str
    suggested_fix: str
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


class LocalDiagnosticMemory:
    """Banco de dados vetorial 100% local com auditoria SQLite e exportação sanitizada opt-in."""

    GLOBAL_TELEMETRY_ENDPOINT = "https://api.datapulse-global.org/v1/telemetry/contribute"

    def __init__(
        self,
        persist_dir: str = "./.datapulse_memory",
        use_sentence_transformers: bool = True,
    ):
        self.persist_path = Path(persist_dir)
        self.persist_path.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(path=str(self.persist_path))
        self.embedding_fn = self._init_embedding_function(use_sentence_transformers)

        self.collection = self.client.get_or_create_collection(
            name="code_diagnostics_memory",
            embedding_function=self.embedding_fn,
            metadata={"description": "Local AST Debugger Memory for Python, SQL, and R"},
        )

        self.sqlite_path = self.persist_path / "audit_sessions.sqlite3"
        self._init_sqlite_audit()

    def _init_embedding_function(self, use_sentence_transformers: bool) -> Any:
        self.semantic = False
        if use_sentence_transformers:
            fn = _get_sentence_transformer_fn()
            if fn is not None:
                self.semantic = True
                return fn
        return DeterministicHashEmbeddingFunction()

    def _init_sqlite_audit(self) -> None:
        with sqlite3.connect(self.sqlite_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    access_point_id TEXT,
                    severity TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def log_audit_event(
        self, event_type: str, access_point_id: str = "", severity: str = "INFO"
    ) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(self.sqlite_path) as conn:
            conn.execute(
                "INSERT INTO audit_log (event_type, access_point_id, severity, timestamp) VALUES (?, ?, ?, ?)",
                (event_type, access_point_id, severity, now),
            )
            conn.commit()

    def save_diagnostic(self, record: DiagnosticRecord) -> int:
        """Armazena um diagnóstico localmente vinculando-o ao ponto de acesso do código."""
        counts = self.save_diagnostics_batch([record])
        return counts.get(record.access_point_id, 1)

    def save_diagnostics_batch(self, records: List[DiagnosticRecord]) -> Dict[str, int]:
        """Persiste uma lista de diagnósticos em lote (1 get + 1 upsert + 1 transação SQLite)."""
        if not records:
            return {}

        ids = [r.access_point_id for r in records]
        existing = self.collection.get(ids=ids)
        prev_counts: Dict[str, int] = {}
        if existing and existing.get("ids"):
            for eid, meta in zip(existing["ids"], existing.get("metadatas") or []):
                if meta:
                    prev_counts[eid] = int(meta.get("recurrence_count", 1))

        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        recurrence_map: Dict[str, int] = {}
        audit_rows: List[tuple] = []
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        for record in records:
            # Segredos/PII nunca são persistidos em claro na memória local
            original_code = redact_sensitive(record.original_code)
            suggested_fix = redact_sensitive(record.suggested_fix)
            summary = redact_sensitive(record.diagnostic_summary)
            recurrence = prev_counts.get(record.access_point_id, 0) + 1
            recurrence_map[record.access_point_id] = recurrence

            documents.append(
                f"Language: {record.language} | Category: {record.error_category}\n"
                f"Summary: {summary}\n"
                f"Code Structure:\n{original_code[:MAX_EMBED_CHARS]}"
            )
            metadatas.append(
                {
                    "file_path": record.file_path,
                    "language": record.language,
                    "access_point_id": record.access_point_id,
                    "node_type": record.node_type,
                    "ast_hash": record.ast_hash,
                    "severity": record.severity,
                    "error_category": record.error_category,
                    "diagnostic_summary": summary,
                    "original_code": original_code,
                    "suggested_fix": suggested_fix,
                    "recurrence_count": recurrence,
                    "timestamp": record.timestamp,
                    "shared_globally": False,
                }
            )
            audit_rows.append(("DIAGNOSTIC_SAVED", record.access_point_id, record.severity, now))

        self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        with sqlite3.connect(self.sqlite_path) as conn:
            conn.executemany(
                "INSERT INTO audit_log (event_type, access_point_id, severity, timestamp) VALUES (?, ?, ?, ?)",
                audit_rows,
            )
            conn.commit()
        return recurrence_map

    def clear_memory(self) -> int:
        """Remove todos os diagnósticos da coleção local (mantendo o log de auditoria)."""
        existing = self.collection.get()
        ids = existing.get("ids") or []
        if ids:
            self.collection.delete(ids=ids)
        self.log_audit_event("MEMORY_CLEARED", f"count={len(ids)}", "INFO")
        return len(ids)

    def retrieve_similar_past_issues(
        self, code_snippet: str, language: str, top_k: int = 3
    ) -> List[Dict[str, Any]]:
        """Busca na memória local se padrões parecidos já foram resolvidos no passado."""
        total = self.collection.count()
        if total == 0:
            return []

        try:
            results = self.collection.query(
                query_texts=[code_snippet],
                n_results=min(top_k, total),
                where={"language": language},
            )
        except Exception:
            return []

        matches: List[Dict[str, Any]] = []
        if results and results.get("metadatas") and results["metadatas"][0]:
            distances = (
                results["distances"][0]
                if results.get("distances") and results["distances"]
                else [0.0] * len(results["metadatas"][0])
            )
            for meta, dist in zip(results["metadatas"][0], distances):
                matches.append({"metadata": meta, "similarity_distance": round(float(dist), 4)})
        return matches

    def get_all_diagnostics(self) -> List[Dict[str, Any]]:
        """Retorna todo o histórico local para alimentar o Dashboard."""
        data = self.collection.get()
        return data.get("metadatas", []) or []

    def prepare_anonymized_global_payload(
        self, selected_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Remove qualquer código-fonte proprietário ou caminhos de arquivos locais.
        Prepara apenas a assinatura matemática da AST e o resumo conceitual da solução.
        """
        if not selected_ids:
            return {"client_version": "1.2.0", "contributions": []}

        records = self.collection.get(ids=selected_ids)
        contributions: List[Dict[str, str]] = []

        for meta in records.get("metadatas", []) or []:
            if not all(k in meta for k in ("language", "ast_hash", "error_category", "severity")):
                continue  # registro incompleto/corrompido: nunca enviar
            contributions.append(
                {
                    "language": str(meta["language"]),
                    "ast_pattern_hash": str(meta["ast_hash"]),
                    "error_category": sanitize_category(str(meta["error_category"])),
                    "severity": str(meta["severity"]),
                    "abstract_diagnostic": sanitize_summary(str(meta.get("diagnostic_summary", ""))),
                    "abstract_solution": "Padrão estrutural refatorado (código-fonte omitido por privacidade).",
                }
            )

        return {
            "client_version": "1.2.0",
            "contributions": contributions,
        }

    @staticmethod
    def _sanitize_pii(text: str) -> str:
        """Remove caminhos locais, e-mails, IPs e segredos do texto (ver src/privacy.py)."""
        return redact_sensitive(text)

    def submit_opt_in_telemetry(
        self, selected_ids: List[str], dry_run: bool = False
    ) -> Dict[str, Any]:
        """Envia o pacote anonimizado mediante autorização explícita do usuário."""
        payload = self.prepare_anonymized_global_payload(selected_ids)
        payload_digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]
        self.log_audit_event(
            "OPT_IN_TELEMETRY_AUTHORIZED",
            f"count={len(payload['contributions'])};payload_sha256={payload_digest}",
            "INFO",
        )

        if dry_run:
            return {"status": "dry_run_success", "payload": payload}

        try:
            response = requests.post(
                self.GLOBAL_TELEMETRY_ENDPOINT,
                json=payload,
                timeout=5,
            )
            response.raise_for_status()
            return {
                "status": "sent",
                "http_status": response.status_code,
                "payload": payload,
            }
        except requests.RequestException as exc:
            # Nada é enviado nem enfileirado: o status reflete a falha de forma honesta
            self.log_audit_event("TELEMETRY_SEND_FAILED", type(exc).__name__, "WARNING")
            return {
                "status": "failed",
                "error": type(exc).__name__,
                "payload": payload,
            }
