import json
import logging
import os
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import AccessPoint, MultiLangASTParser
from src.privacy import redact_sensitive
from src.rules import evaluate

try:
    from google import genai
    from google.genai import types

    HAS_GENAI = True
except Exception:
    HAS_GENAI = False


logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """Você é o Motor de Diagnóstico Estático do DataPulse. Sua função é analisar blocos de código (Python, SQL, R, JavaScript/TypeScript) extraídos via AST, juntamente com suas árvores sintáticas e histórico de memória vetorial.

REGRAS ESTRITAS DE SEGURANÇA:
1. Você opera em modo 100% READ-ONLY. Jamais gere comandos de sistema, scripts de alteração de arquivos ou instruções de execução direta.
2. Foque em bugs de engenharia de dados e backend: vazamento de memória em DataFrames, queries SQL sem índice ou vulneráveis a injeção, falta de vetorização em R/Python, problemas de tipagem e concorrência, e em JavaScript/Node: eval/injeção de comando, I/O síncrono no event loop, ReDoS, promises sem tratamento e segredos hardcoded.
3. Compare o bloco atual com os "Casos Similares da Memória Local" fornecidos no contexto. Se for uma reincidência, destaque isso.
4. Retorne EXCLUSIVAMENTE um objeto JSON válido seguindo o schema `DiagnosticReport`."""


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
    """Orquestrador Antigravity: une MultiLangASTParser, RAG no ChromaDB e Google GenAI (opt-in)."""

    # Reincidência semântica só conta se o caso for muito próximo (ou tiver o mesmo ast_hash)
    SIMILARITY_THRESHOLD = 0.5

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

    def analyze_access_point(
        self, ap: AccessPoint, persist_to_memory: bool = True
    ) -> Optional[DiagnosticRecord]:
        """Executa RAG local + análise estática (LLM opt-in ou regras AST) sobre um AccessPoint."""
        similar_cases = self.memory.retrieve_similar_past_issues(
            code_snippet=ap.code_snippet,
            language=ap.language,
            top_k=3,
        )
        similar_cases = self._filter_true_recurrences(similar_cases, ap)

        report = self._invoke_llm_or_heuristic(ap, similar_cases)
        if not report or not report.has_issue:
            return None

        record = DiagnosticRecord(
            file_path=ap.file_path,
            language=ap.language,
            access_point_id=ap.access_id,
            node_type=ap.node_type,
            ast_hash=ap.ast_hash,
            severity=report.severity,
            error_category=report.error_category,
            diagnostic_summary=report.diagnostic_summary,
            original_code=ap.code_snippet,
            suggested_fix=report.suggested_fix,
        )

        if persist_to_memory:
            self.memory.save_diagnostic(record)

        return record

    def scan_directory(
        self, directory_path: str, languages: Optional[List[str]] = None
    ) -> List[DiagnosticRecord]:
        """Mapeia todos os pontos de acesso do diretório em modo Read-Only e diagnostica cada nó."""
        access_points = self.parser.parse_directory_readonly(directory_path, languages=languages)
        diagnostics: List[DiagnosticRecord] = []

        for ap in access_points:
            record = self.analyze_access_point(ap, persist_to_memory=False)
            if record is not None:
                diagnostics.append(record)

        if diagnostics:
            self.memory.save_diagnostics_batch(diagnostics)

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

    def _invoke_llm_or_heuristic(
        self, ap: AccessPoint, similar_cases: List[Dict[str, Any]]
    ) -> Optional[DiagnosticReport]:
        """Usa o Gemini (opt-in, código redigido) com Structured Outputs; senão, as regras estáticas."""
        if self.client is not None:
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

        return self._static_heuristic_diagnosis(ap, similar_cases)

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