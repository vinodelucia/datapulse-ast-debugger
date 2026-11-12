import json
import os
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import AccessPoint, MultiLangASTParser

try:
    from google import genai
    from google.genai import types

    HAS_GENAI = True
except Exception:
    HAS_GENAI = False


SYSTEM_PROMPT = """Você é o Motor de Diagnóstico Estático do DataPulse. Sua função é analisar blocos de código (Python, SQL, R) extraídos via AST, juntamente com suas árvores sintáticas e histórico de memória vetorial.

REGRAS ESTRITAS DE SEGURANÇA:
1. Você opera em modo 100% READ-ONLY. Jamais gere comandos de sistema, scripts de alteração de arquivos ou instruções de execução direta.
2. Foque em bugs de engenharia de dados: vazamento de memória em DataFrames, queries SQL sem índice ou vulneráveis a injeção, falta de vetorização em R/Python, problemas de tipagem e concorrência.
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
    """Orquestrador Antigravity: une MultiLangASTParser, RAG no ChromaDB e Google GenAI (gemini-2.5-pro)."""

    def __init__(
        self,
        memory: Optional[LocalDiagnosticMemory] = None,
        parser: Optional[MultiLangASTParser] = None,
        model_name: str = "gemini-2.5-pro",
        api_key: Optional[str] = None,
    ):
        self.memory = memory or LocalDiagnosticMemory()
        self.parser = parser or MultiLangASTParser()
        self.model_name = model_name
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.client = None

        if HAS_GENAI and self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    def analyze_access_point(
        self, ap: AccessPoint, persist_to_memory: bool = True
    ) -> Optional[DiagnosticRecord]:
        """Executa RAG local + análise estática (LLM ou motor heurístico AST) sobre um AccessPoint."""
        similar_cases = self.memory.retrieve_similar_past_issues(
            code_snippet=ap.code_snippet,
            language=ap.language,
            top_k=3,
        )

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
            record = self.analyze_access_point(ap, persist_to_memory=True)
            if record is not None:
                diagnostics.append(record)

        return diagnostics

    def _invoke_llm_or_heuristic(
        self, ap: AccessPoint, similar_cases: List[Dict[str, Any]]
    ) -> Optional[DiagnosticReport]:
        """Chama o Gemini 2.5 Pro com Structured Outputs ou utiliza motor estático determinístico."""
        if self.client is not None:
            try:
                rag_context = self._format_rag_context(similar_cases)
                user_prompt = (
                    f"### Ponto de Acesso AST\n"
                    f"- ID: `{ap.access_id}`\n"
                    f"- Linguagem: `{ap.language}`\n"
                    f"- Tipo de Nó AST: `{ap.node_type}`\n"
                    f"- Linhas: {ap.start_line} a {ap.end_line}\n"
                    f"- S-Expression AST:\n```\n{ap.ast_sexp[:1500]}\n```\n\n"
                    f"### Casos Similares da Memória Local (RAG)\n{rag_context}\n\n"
                    f"### Código-Fonte Original (Read-Only)\n```{ap.language}\n{ap.code_snippet}\n```"
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
            except Exception:
                pass

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
        """Motor de análise estática determinístico para execução offline/testes sem chave de API."""
        code = ap.code_snippet
        reincidence_note = (
            f" [Reincidência detectada no RAG: {len(similar_cases)} caso(s) similar(es) na memória]."
            if similar_cases
            else ""
        )

        if ap.language == "python":
            if ".iterrows()" in code:
                return DiagnosticReport(
                    has_issue=True,
                    severity="HIGH",
                    error_category="Pandas_Iterrows_Bottleneck",
                    chain_of_thought="O nó AST contém iteração linha a linha via .iterrows() em DataFrame, causando boxing/unboxing de Series a cada linha.",
                    diagnostic_summary=(
                        "Loop explícito com `.iterrows()` detectado em DataFrame. Causa degradação severa de CPU e alocação desnecessária de memória."
                        + reincidence_note
                    ),
                    suggested_fix=(
                        "# Substituir loop .iterrows() por operação vetorizada C-level:\n"
                        "df['tax'] = df['price'] * 0.15\n"
                        "df['net_total'] = df['price'] + df['tax']"
                    ),
                )
            import re

            if re.search(r"(?m)^\s*\w+\[[^\]]+\]\[[^\]]+\]\s*=", code):
                return DiagnosticReport(
                    has_issue=True,
                    severity="MEDIUM",
                    error_category="Pandas_ChainedIndexing_Warning",
                    chain_of_thought="Indexação encadeada df[][]=val identificada no lado esquerdo de atribuição na árvore sintática.",
                    diagnostic_summary=(
                        "Uso de indexação encadeada `df[][]=val` pode operar sobre cópia temporária e gerar `SettingWithCopyWarning` silencioso."
                        + reincidence_note
                    ),
                    suggested_fix="df.loc[df['status'] == 'ACTIVE', 'discount'] = 0.10",
                )
            if "f\"SELECT" in code or "f'SELECT" in code or "+ user_" in code:
                return DiagnosticReport(
                    has_issue=True,
                    severity="CRITICAL",
                    error_category="SQL_Injection_Vulnerability",
                    chain_of_thought="Interpolação direta de string em query SQL dentro de função Python.",
                    diagnostic_summary=(
                        "Construção de query SQL via f-string/concatenação expõe o pipeline a SQL Injection crítico."
                        + reincidence_note
                    ),
                    suggested_fix=(
                        "cursor.execute('SELECT * FROM users WHERE user_id = :uid', {'uid': user_id})"
                    ),
                )
            if "shell=True" in code and ("subprocess." in code or "Popen(" in code or "run(" in code):
                return DiagnosticReport(
                    has_issue=True,
                    severity="HIGH",
                    error_category="Subprocess_Shell_Injection_Risk",
                    chain_of_thought="Chamada subprocess com shell=True identificada no nó AST.",
                    diagnostic_summary=(
                        "Execução de subprocesso com `shell=True` permite injeção de comandos de shell se houver interpolação de variáveis externas."
                        + reincidence_note
                    ),
                    suggested_fix="subprocess.run(['cmd', 'arg1', 'arg2'], shell=False, check=True)",
                )
            if re.search(r"except(?:\s+\w+)?\s*:\s*\n\s*pass\b", code) or "except:" in code:
                return DiagnosticReport(
                    has_issue=True,
                    severity="LOW",
                    error_category="Silent_Exception_Swallowing",
                    chain_of_thought="Bloco try/except genérico silenciando exceções na AST sem telemetria ou re-raise.",
                    diagnostic_summary=(
                        "Captura silenciosa de exceção (`bare except:` ou `except Exception: pass`) oculta falhas de pipeline e dificulta rastreabilidade."
                        + reincidence_note
                    ),
                    suggested_fix="except Exception as exc:\n    logger.warning('Falha controlada na operação: %s', exc)",
                )

        elif ap.language == "sql":
            upper_code = code.upper()
            if "SELECT *" in upper_code and ("CROSS JOIN" in upper_code or "WHERE" not in upper_code or "LIKE '%" in upper_code):
                return DiagnosticReport(
                    has_issue=True,
                    severity="CRITICAL" if "CROSS JOIN" in upper_code else "HIGH",
                    error_category="SQL_FullTableScan",
                    chain_of_thought="Query utiliza SELECT * combinado com predicado não-sargable (LIKE '%...') ou ausência de partição/índice.",
                    diagnostic_summary=(
                        "Projeção `SELECT *` com filtro leading-wildcard (`LIKE '%...'`) ou `CROSS JOIN` força Full Table Scan e alto custo de I/O."
                        + reincidence_note
                    ),
                    suggested_fix=(
                        "SELECT order_id, customer_id, order_total, created_at\n"
                        "FROM analytics.fact_orders\n"
                        "WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'\n"
                        "  AND status = 'COMPLETED';"
                    ),
                )

        elif ap.language == "r":
            if "for (" in code or "for(" in code or "rbind(" in code:
                return DiagnosticReport(
                    has_issue=True,
                    severity="HIGH",
                    error_category="R_Vectorization_Missing",
                    chain_of_thought="Crescimento iterativo de objeto ou loop explícito em R copiando vetor em memória a cada iteração.",
                    diagnostic_summary=(
                        "Loop `for` com realocação incremental (`rbind` / indexação sequencial) em R gera complexidade quadrática O(N²) de memória."
                        + reincidence_note
                    ),
                    suggested_fix=(
                        "normalize_metrics <- function(df) {\n"
                        "  df$z_score <- (df$value - mean(df$value, na.rm = TRUE)) / sd(df$value, na.rm = TRUE)\n"
                        "  return(df)\n"
                        "}"
                    ),
                )

        return None
