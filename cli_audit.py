"""
CLI Integrado do DataPulse AST Debugger para execução via Agente Antigravity em qualquer workspace.
Opera em modo 100% Read-Only sobre o projeto alvo e sincroniza com a memória vetorial local (ChromaDB).
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.analyzer_agent import DataPulseAnalyzerAgent
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser


def run_cli_audit(
    target_path: str,
    languages: List[str],
    memory_dir: str,
    output_format: str = "markdown",
    fast_embeddings: bool = False,
    allow_llm: bool = False,
) -> int:
    target = Path(target_path).resolve()
    if not target.exists():
        print(f"Erro: Caminho alvo não encontrado: {target}", file=sys.stderr)
        return 1

    memory = LocalDiagnosticMemory(
        persist_dir=memory_dir,
        use_sentence_transformers=not fast_embeddings,
    )
    parser = MultiLangASTParser()
    agent = DataPulseAnalyzerAgent(memory=memory, parser=parser, allow_llm=allow_llm)

    if target.is_file():
        access_points = parser.parse_file_readonly(str(target))
        diagnostics: List[DiagnosticRecord] = []
        for ap in access_points:
            rec = agent.analyze_access_point(ap, persist_to_memory=True)
            if rec is not None:
                diagnostics.append(rec)
    else:
        access_points = parser.parse_directory_readonly(str(target), languages=languages)
        diagnostics = []
        for ap in access_points:
            rec = agent.analyze_access_point(ap, persist_to_memory=True)
            if rec is not None:
                diagnostics.append(rec)

    all_mem = memory.get_all_diagnostics()
    rec_map = {m["access_point_id"]: m.get("recurrence_count", 1) for m in all_mem}

    if output_format == "json":
        payload = {
            "target": str(target),
            "mode": "100% Read-Only",
            "total_access_points_scanned": len(access_points),
            "issues_found": len(diagnostics),
            "diagnostics": [
                {
                    **d.model_dump(),
                    "recurrence_count": rec_map.get(d.access_point_id, 1),
                }
                for d in diagnostics
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    # Output em Markdown estruturado para o Agente Antigravity
    print(f"# 🛡️ Relatório DataPulse AST Debugger")
    print(f"- **Alvo Auditado:** `{target}`")
    print(f"- **Modo de Operação:** `100% Read-Only (Zero-Execution)`")
    print(f"- **Pontos de Acesso AST Mapeados:** `{len(access_points)}`")
    print(f"- **Alertas Diagnosticados:** `{len(diagnostics)}`")
    print(f"- **Memória Vetorial (ChromaDB):** `{Path(memory_dir).resolve()}`\n")

    if not diagnostics:
        print("✅ **Nenhum gargalo crítico ou vulnerabilidade lógica detectada nos nós AST analisados.**")
        return 0

    print("## 🔬 Diagnósticos por Ponto de Acesso\n")
    for idx, d in enumerate(diagnostics, 1):
        rec_count = rec_map.get(d.access_point_id, 1)
        print(
            f"### {idx}. [{d.severity}] `{d.access_point_id}` — `{d.error_category}` (Recorrência: {rec_count}x)"
        )
        print(f"- **Arquivo:** `{d.file_path}`")
        print(f"- **Hash Estrutural AST:** `{d.ast_hash}`")
        print(f"- **Diagnóstico:** {d.diagnostic_summary}\n")
        print("**Código Original (Read-Only):**")
        print(f"```{d.language}\n{d.original_code}\n```\n")
        print("**Sugestão de Refatoração:**")
        print(f"```{d.language}\n{d.suggested_fix}\n```\n")
        print("---\n")

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
        choices=["markdown", "json"],
        help="Formato de saída do relatório (markdown ou json).",
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
        )
    )


if __name__ == "__main__":
    main()
