import json
import logging
import os
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from src.config import DataPulseConfig
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import AccessPoint, MultiLangASTParser
from src.privacy import redact_sensitive
from src.rules import evaluate, evaluate_all

try:
    from google import genai
    from google.genai import types

    HAS_GENAI = True
except Exception:
    HAS_GENAI = False


logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Você é o Motor de Diagnóstico Estático do DataPulse. Sua função é analisar blocos de código (Python, SQL, R, JavaScript/TypeScript) extraídos via AST, juntamente com suas árvores sintáticas e histórico de memória vetorial.

REGRAS ESTRITAS DE SEGURANÇA E TRIAGEM:
1. Você opera em modo 100% READ-ONLY. Jamais gere comandos de sistema, scripts de alteração de arquivos ou instruções de execução direta.
2. Foque em bugs de engenharia de dados e backend: vazamento de memória em DataFrames, queries SQL sem índice ou vulneráveis a injeção, falta de vetorização em R/Python, problemas de tipagem e concorrência, e em JavaScript/Node: eval/injeção de comando, SSRF, SSTI, I/O síncrono no event loop, ReDoS, promises sem tratamento e segredos hardcoded.
3. Gate de Triagem (evite falsos positivos): verifique se a entrada é realmente externa (não constante literal) e se já existe guarda/sanitizador (`SafeLoader`, `defusedxml`, `try/catch`, `Object.hasOwn`, query parametrizada) antes de marcar `has_issue=true`. Reserve `CRITICAL` para RCE, SQLi, mutação destrutiva sem `WHERE` ou credencial exposta.
4. Compare o bloco atual com os "Casos Similares da Memória Local" fornecidos no contexto. Se for uma reincidência, destaque isso.
5. Retorne EXCLUSIVAMENTE um objeto JSON válido seguindo o schema `DiagnosticReport`."""


class DiagnosticReport(BaseModel):
    """Schema de saída estruturada do LLM (Chain-of-Thought + Diagnóstico)."""

    has_issue: bool = Field(
        description="True se o bloco de código contém bug lógico, risco de segurança ou gargalo de performance."
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        description="Nível de severidade do problema identificado."
    )
    error_category: str = Field(
        description="Categoria concisa do problema (ex: MemoryLeak_Pandas, SQL_FullTableScan, R_Vectorization_Missing)."
    )
    chain_of_thought: str = Field(
        description="Raciocínio passo a passo (Static Tracing) sobre o fluxo de dados na AST."
    )
    diagnostic_summary: str = Field(
        description="Explicação técnica clara do problema e se há reincidência na memória RAG."
    )
    suggested_fix: str = Field(
        description="Bloco de código refatorado sugerido (apenas para visualização lado a lado)."
    )


class DataPulseAnalyzerAgent:
    """Orquestrador Antigravity: une MultiLangASTParser, RAG em lote e Google GenAI (opt-in)."""

    # Reincidência semântica só conta se o caso for muito próximo (ou tiver o mesmo ast_hash)
    SIMILARITY_THRESHOLD = 0.5
    _SEVERITY_WEIGHTS = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}

    def __init__(
        self,
        memory: Optional[LocalDiagnosticMemory] = None,
        parser: Optional[MultiLangASTParser] = None,
        model_name: str = "gemini-2.5-pro",
        api_key: Optional[str] = None,
        allow_llm: Optional[bool] = None,
    ):
        self.memory = memory or LocalDiagnosticMemory()
        self.parser = parser or MultiLangASTParser()
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.client = None

        # O código só sai da máquina rumo ao LLM com opt-in explícito (flag ou DATAPULSE_ALLOW_LLM=1)
        if allow_llm is None:
            allow_llm = os.environ.get("DATAPULSE_ALLOW_LLM", "").lower() in ("1", "true", "yes")
        self.allow_llm = bool(allow_llm)

        if self.allow_llm and HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as exc:
                logger.warning("Falha ao iniciar cliente Gemini; usando motor heurístico: %s", exc)
                self.client = None

    @classmethod
    def compute_health_score(
        cls,
        total_access_points: int,
        diagnostics: List[DiagnosticRecord],
        avg_complexity: float = 1.0,
    ) -> Dict[str, Any]:
        """Calcula Health Score (0-100) e nota (A-F) ponderados por severidade e volume."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        penalty = 0
        for d in diagnostics:
            sev = str(d.severity).upper()
            if sev in counts:
                counts[sev] += 1
            penalty += cls._SEVERITY_WEIGHTS.get(sev, 1)

        denom = max(1.0, total_access_points * 0.5)
        scaled_penalty = penalty / max(1.0, denom / 5.0)
        score = max(0, min(100, round(100 - scaled_penalty)))
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "grade": grade,
            "avg_complexity": round(float(avg_complexity), 2),
            "by_severity": counts,
        }

    def analyze_access_point(
        self, ap: AccessPoint, persist_to_memory: bool = True
    ) -> Optional[DiagnosticRecord]:
        """Compatibilidade v1: retorna apenas o achado de maior severidade para o AccessPoint."""
        records = self.analyze_access_point_all(
            ap,
            persist_to_memory=persist_to_memory,
            config=DataPulseConfig(multi_finding=False),
        )
        return records[0] if records else None

    def analyze_access_point_all(
        self,
        ap: AccessPoint,
        persist_to_memory: bool = True,
        precomputed_similar: Optional[List[Dict[str, Any]]] = None,
        config: Optional[DataPulseConfig] = None,
    ) -> List[DiagnosticRecord]:
        """Executa RAG local + análise estática multi-achado sobre um AccessPoint."""
        cfg = config or DataPulseConfig()
        raw_similar = (
            precomputed_similar
            if precomputed_similar is not None
            else self.memory.retrieve_similar_past_issues(
                code_snippet=ap.code_snippet,
                language=ap.language,
                top_k=3,
            )
        )
        similar_cases = self._filter_true_recurrences(raw_similar, ap)

        if self.client is not None:
            llm_report = self._invoke_llm(ap, similar_cases)
            if llm_report is not None:
                if not llm_report.has_issue:
                    return []
                rec = DiagnosticRecord(
                    file_path=ap.file_path,
                    language=ap.language,
                    access_point_id=ap.access_id,
                    node_type=ap.node_type,
                    ast_hash=ap.ast_hash,
                    severity=llm_report.severity,
                    error_category=llm_report.error_category,
                    diagnostic_summary=llm_report.diagnostic_summary,
                    original_code=ap.code_snippet,
                    suggested_fix=llm_report.suggested_fix,
                    start_line=ap.start_line,
                    end_line=ap.end_line,
                    cyclomatic_complexity=ap.cyclomatic_complexity,
                    source="llm",
                )
                if persist_to_memory:
                    self.memory.save_diagnostics_batch([rec])
                return [rec]

        matches = evaluate_all(
            ap.language,
            ap.code_snippet,
            disable_rules=cfg.disable_rules,
            min_severity=cfg.min_severity,
            complexity_threshold=cfg.complexity_threshold,
            cyclomatic_complexity=ap.cyclomatic_complexity,
            sql_dialect=cfg.sql_dialect,
        )
        if not matches:
            return []
        if not cfg.multi_finding:
            matches = matches[:1]

        note = (
            f" [Reincidência detectada no RAG: {len(similar_cases)} caso(s) recorrente(s) na memória]."
            if similar_cases
            else ""
        )
        records: List[DiagnosticRecord] = []
        for idx, match in enumerate(matches):
            rec_id = ap.access_id if idx == 0 else f"{ap.access_id}::{match.rule.category}"
            line_num = min(ap.end_line, ap.start_line + match.line_offset)
            records.append(
                DiagnosticRecord(
                    file_path=ap.file_path,
                    language=ap.language,
                    access_point_id=rec_id,
                    node_type=ap.node_type,
                    ast_hash=ap.ast_hash,
                    severity=match.rule.severity,
                    error_category=match.rule.category,
                    diagnostic_summary=match.rule.summary + note,
                    original_code=ap.code_snippet,
                    suggested_fix=match.rule.fix,
                    start_line=line_num,
                    end_line=ap.end_line,
                    cyclomatic_complexity=ap.cyclomatic_complexity,
                    source="heuristic",
                )
            )

        if persist_to_memory and records:
            self.memory.save_diagnostics_batch(records)

        return records

    def scan_directory(
        self,
        directory_path: str,
        languages: Optional[List[str]] = None,
        config: Optional[DataPulseConfig] = None,
        incremental: bool = False,
    ) -> List[DiagnosticRecord]:
        """Mapeia AccessPoints em Read-Only, consulta RAG em lote e diagnostica todos os achados."""
        cfg = config or DataPulseConfig.load(directory_path)
        access_points = self.parser.parse_directory_readonly(
            directory_path,
            languages=languages,
            extra_ignore_dirs=cfg.ignore_paths,
            sql_dialect=cfg.sql_dialect,
        )

        new_file_hashes: Dict[str, str] = {}
        if access_points:
            known_hashes = self.memory.get_scanned_file_hashes() if incremental else {}
            filtered: List[AccessPoint] = []
            file_hash_cache: Dict[str, str] = {}
            for ap in access_points:
                if ap.file_path not in file_hash_cache:
                    try:
                        file_hash_cache[ap.file_path] = MultiLangASTParser.compute_file_sha256(ap.file_path)
                    except OSError:
                        file_hash_cache[ap.file_path] = ""
                fhash = file_hash_cache[ap.file_path]
                if incremental and fhash and known_hashes.get(ap.file_path) == fhash:
                    continue
                if fhash:
                    new_file_hashes[ap.file_path] = fhash
                filtered.append(ap)
            access_points = filtered

        if not access_points:
            return []

        batch_similar = self.memory.retrieve_similar_batch(
            [(ap.code_snippet, ap.language) for ap in access_points],
            top_k=3,
        )

        diagnostics: List[DiagnosticRecord] = []
        for ap, similar in zip(access_points, batch_similar):
            diagnostics.extend(
                self.analyze_access_point_all(
                    ap,
                    persist_to_memory=False,
                    precomputed_similar=similar,
                    config=cfg,
                )
            )

        if diagnostics:
            self.memory.save_diagnostics_batch(diagnostics)
        if new_file_hashes:
            self.memory.mark_files_scanned(new_file_hashes)

        return diagnostics

    def _filter_true_recurrences(
        self, similar_cases: List[Dict[str, Any]], ap: AccessPoint
    ) -> List[Dict[str, Any]]:
        """Mantém só casos realmente recorrentes: mesmo ast_hash ou distância semântica baixa."""
        semantic = getattr(self.memory, "semantic", False)
        kept = []
        for case in similar_cases:
            same_hash = case.get("metadata", {}).get("ast_hash") == ap.ast_hash
            close = semantic and case.get("similarity_distance", 9.9) < self.SIMILARITY_THRESHOLD
            if same_hash or close:
                kept.append(case)
        return kept

    def _invoke_llm(
        self, ap: AccessPoint, similar_cases: List[Dict[str, Any]]
    ) -> Optional[DiagnosticReport]:
        """Chama o Gemini (opt-in, código redigido) com Structured Outputs."""
        if self.client is None:
            return None
        try:
            rag_context = self._format_rag_context(similar_cases)
            user_prompt = (
                f"### Ponto de Acesso AST\n"
                f"- ID: `{ap.access_id}`\n"
                f"- Linguagem: `{ap.language}`\n"
                f"- Tipo de Nó AST: `{ap.node_type}`\n"
                f"- Linhas: {ap.start_line} a {ap.end_line}\n\n"
                f"### Casos Similares da Memória Local (RAG)\n{rag_context}\n\n"
                f"### Código-Fonte Original (Read-Only, segredos/PII redigidos)\n"
                f"```{ap.language}\n{redact_sensitive(ap.code_snippet)}\n```"
            )

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=0.1,
                    response_mime_type="application/json",
                    response_schema=DiagnosticReport,
                ),
            )
            if response and response.text:
                data = json.loads(response.text)
                return DiagnosticReport(**data)
        except Exception as exc:
            logger.warning(
                "Falha na análise via LLM em %s; usando regras estáticas: %s", ap.access_id, exc
            )
        return None

    @staticmethod
    def _format_rag_context(similar_cases: List[Dict[str, Any]]) -> str:
        if not similar_cases:
            return "Nenhum caso similar registrado anteriormente na memória local."
        lines = []
        for idx, item in enumerate(similar_cases, 1):
            meta = item.get("metadata", {})
            dist = item.get("similarity_distance", 0.0)
            lines.append(
                f"{idx}. [{meta.get('severity')}] Categoria: {meta.get('error_category')} "
                f"(Distância: {dist}, Recorrências: {meta.get('recurrence_count', 1)}x) — "
                f"{meta.get('diagnostic_summary')}"
            )
        return "\n".join(lines)

    def _static_heuristic_diagnosis(
        self, ap: AccessPoint, similar_cases: List[Dict[str, Any]]
    ) -> Optional[DiagnosticReport]:
        """Regras estáticas determinísticas (offline); vence a de maior severidade."""
        rule = evaluate(ap.language, ap.code_snippet)
        if rule is None:
            return None
        note = (
            f" [Reincidência detectada no RAG: {len(similar_cases)} caso(s) recorrente(s) na memória]."
            if similar_cases
            else ""
        )
        return DiagnosticReport(
            has_issue=True,
            severity=rule.severity,
            error_category=rule.category,
            chain_of_thought=rule.chain_of_thought,
            diagnostic_summary=rule.summary + note,
            suggested_fix=rule.fix,
        )
