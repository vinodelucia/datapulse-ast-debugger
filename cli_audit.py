"""
CLI Integrado do DataPulse AST Debugger para execução via Agente Antigravity e CI/CD.
Opera em modo 100% Read-Only sobre o projeto alvo e sincroniza com a memória vetorial local (ChromaDB).
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src import __version__
from src.analyzer_agent import DataPulseAnalyzerAgent
from src.config import DataPulseConfig
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser
from src.rules import SEVERITY_ORDER
from src.sarif_exporter import build_sarif_report


def run_cli_audit(
    target_path: str,
    languages: List[str],
    memory_dir: str,
    output_format: str = "markdown",
    fast_embeddings: bool = False,
    allow_llm: bool = False,
    output_file: Optional[str] = None,
    fail_on: Optional[str] = None,
    incremental: bool = False,
    sql_dialect: Optional[str] = None,
    single_finding: bool = False,
) -> int:
    target = Path(target_path).resolve()
    if not target.exists():
        print(f"Erro: Caminho alvo não encontrado: {target}", file=sys.stderr)
        return 1

    cfg = DataPulseConfig.load(target)
    if sql_dialect is not None:
        cfg.sql_dialect = sql_dialect
    if single_finding:
        cfg.multi_finding = False

    memory = LocalDiagnosticMemory(
        persist_dir=memory_dir,
        use_sentence_transformers=not fast_embeddings,
    )
    parser = MultiLangASTParser()
    agent = DataPulseAnalyzerAgent(memory=memory, parser=parser, allow_llm=allow_llm)

    access_points = (
        parser.parse_file_readonly(str(target), sql_dialect=cfg.sql_dialect)
        if target.is_file()
        else parser.parse_directory_readonly(
            str(target),
            languages=languages,
            extra_ignore_dirs=cfg.ignore_paths,
            sql_dialect=cfg.sql_dialect,
        )
    )

    new_file_hashes: Dict[str, str] = {}
    if access_points:
        known = memory.get_scanned_file_hashes() if incremental else {}
        filtered = []
        hash_cache: Dict[str, str] = {}
        for ap in access_points:
            if ap.file_path not in hash_cache:
                try:
                    hash_cache[ap.file_path] = MultiLangASTParser.compute_file_sha256(ap.file_path)
                except OSError:
                    hash_cache[ap.file_path] = ""
            digest = hash_cache[ap.file_path]
            if incremental and digest and known.get(ap.file_path) == digest:
                continue
            if digest:
                new_file_hashes[ap.file_path] = digest
            filtered.append(ap)
        access_points = filtered

    batch_similar = memory.retrieve_similar_batch(
        [(ap.code_snippet, ap.language) for ap in access_points],
        top_k=3,
    )
    diagnostics: List[DiagnosticRecord] = []
    for ap, similar in zip(access_points, batch_similar):
        diagnostics.extend(
            agent.analyze_access_point_all(
                ap,
                persist_to_memory=False,
                precomputed_similar=similar,
                config=cfg,
            )
        )

    if diagnostics:
        memory.save_diagnostics_batch(diagnostics)
    if new_file_hashes:
        memory.mark_files_scanned(new_file_hashes)

    all_mem = memory.get_all_diagnostics()
    rec_map = {m["access_point_id"]: m.get("recurrence_count", 1) for m in all_mem}
    avg_cc = (
        sum(ap.cyclomatic_complexity for ap in access_points) / len(access_points)
        if access_points
        else 1.0
    )
    health = DataPulseAnalyzerAgent.compute_health_score(
        len(access_points), diagnostics, avg_complexity=avg_cc
    )

    base_dir = str(target.parent if target.is_file() else target)
    if output_format == "sarif":
        sarif_doc = build_sarif_report(diagnostics, tool_version=__version__, base_dir=base_dir)
        rendered = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
    elif output_format == "json":
        payload = {
            "target": str(target),
            "mode": "100% Read-Only",
            "total_access_points_scanned": len(access_points),
            "issues_found": len(diagnostics),
            "health_score": health["score"],
            "grade": health["grade"],
            "avg_cyclomatic_complexity": health["avg_complexity"],
            "diagnostics": [
                {
                    **d.model_dump(),
                    "recurrence_count": rec_map.get(d.access_point_id, 1),
                }
                for d in diagnostics
            ],
        }
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        lines: List[str] = [
            "# 🛡️ Relatório DataPulse AST Debugger",
            f"- **Alvo Auditado:** `{target}`",
            "- **Modo de Operação:** `100% Read-Only (Zero-Execution)`",
            f"- **Pontos de Acesso AST Mapeados:** `{len(access_points)}`",
            f"- **Alertas Diagnosticados:** `{len(diagnostics)}`",
            f"- **Health Score:** `{health['score']}/100 ({health['grade']})` | **Complexidade Média (CC):** `{health['avg_complexity']}`",
            f"- **Memória Vetorial (ChromaDB):** `{Path(memory_dir).resolve()}`\n",
        ]
        if not diagnostics:
            lines.append("✅ **Nenhum gargalo crítico ou vulnerabilidade lógica detectada nos nós AST analisados.**")
        else:
            lines.append("## 🔬 Diagnósticos por Ponto de Acesso\n")
            for idx, d in enumerate(diagnostics, 1):
                rec_count = rec_map.get(d.access_point_id, 1)
                lines.append(
                    f"### {idx}. [{d.severity}] `{d.access_point_id}` — `{d.error_category}` (Recorrência: {rec_count}x | CC: {d.cyclomatic_complexity})"
                )
                lines.append(f"- **Arquivo:** `{d.file_path}` (L{d.start_line}-L{d.end_line})")
                lines.append(f"- **Hash Estrutural AST:** `{d.ast_hash}`")
                lines.append(f"- **Diagnóstico:** {d.diagnostic_summary}\n")
                lines.append("**Código Original (Read-Only):**")
                lines.append(f"```{d.language}\n{d.original_code}\n```\n")
                lines.append("**Sugestão de Refatoração:**")
                lines.append(f"```{d.language}\n{d.suggested_fix}\n```\n")
                lines.append("---\n")
        rendered = "\n".join(lines)

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    if fail_on:
        threshold = SEVERITY_ORDER.get(fail_on.upper(), 4)
        if any(SEVERITY_ORDER.get(d.severity.upper(), 0) >= threshold for d in diagnostics):
            return 2

    return 0


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    default_mem = str(ROOT_DIR / ".datapulse_memory")
    arg_parser = argparse.ArgumentParser(
        description="DataPulse AST Debugger - Read-Only CLI Runner"
    )
    arg_parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Caminho do diretório ou arquivo a ser auditado em modo Read-Only.",
    )
    arg_parser.add_argument(
        "--languages",
        "-l",
        nargs="+",
        default=["python", "sql", "r", "javascript"],
        choices=["python", "sql", "r", "javascript"],
        help="Linguagens monitoradas (padrão: python sql r javascript).",
    )
    arg_parser.add_argument(
        "--memory-dir",
        "-m",
        default=default_mem,
        help="Diretório de persistência do ChromaDB local.",
    )
    arg_parser.add_argument(
        "--format",
        "-f",
        default="markdown",
        choices=["markdown", "json", "sarif"],
        help="Formato de saída do relatório (markdown, json ou sarif).",
    )
    arg_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Caminho opcional para gravar o relatório em arquivo.",
    )
    arg_parser.add_argument(
        "--fail-on",
        default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Retorna código 2 se houver alertas >= severidade informada (Quality Gate CI).",
    )
    arg_parser.add_argument(
        "--incremental",
        action="store_true",
        help="Ignora arquivos inalterados cujo SHA-256 já está em cache no SQLite.",
    )
    arg_parser.add_argument(
        "--sql-dialect",
        default=None,
        help="Dialeto SQL para o SQLGlot (ex.: postgres, bigquery, snowflake, duckdb, tsql, spark, mysql).",
    )
    arg_parser.add_argument(
        "--single-finding",
        action="store_true",
        help="Limita a saída a 1 achado de maior severidade por AccessPoint.",
    )
    arg_parser.add_argument(
        "--fast-embeddings",
        action="store_true",
        help="Usa embedding determinístico instantâneo sem carregar pesos do SentenceTransformer.",
    )
    arg_parser.add_argument(
        "--allow-llm",
        action="store_true",
        help="Opt-in: envia o código (com segredos/PII redigidos) ao Gemini se GEMINI_API_KEY estiver definida. "
        "Por padrão nada sai da sua máquina.",
    )

    args = arg_parser.parse_args()
    sys.exit(
        run_cli_audit(
            target_path=args.target,
            languages=args.languages,
            memory_dir=args.memory_dir,
            output_format=args.format,
            fast_embeddings=args.fast_embeddings,
            allow_llm=args.allow_llm,
            output_file=args.output,
            fail_on=args.fail_on,
            incremental=args.incremental,
            sql_dialect=args.sql_dialect,
            single_finding=args.single_finding,
        )
    )


if __name__ == "__main__":
    main()
