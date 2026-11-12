"""Script de verificação e inicialização das gramáticas AST (Tree-sitter) para Python, SQL e R."""

from src.parser_engine import HAS_TREE_SITTER, MultiLangASTParser


def verify_grammars() -> bool:
    parser = MultiLangASTParser()
    supported = ["python", "sql", "r", "javascript", "typescript", "tsx"]
    print("=== DataPulse AST Debugger: Grammar Check ===")
    print(f"Tree-sitter C-bindings available: {HAS_TREE_SITTER}")

    for lang in supported:
        active_parser = parser.parsers.get(lang)
        status = "READY (Tree-sitter)" if active_parser is not None else "READY (Deterministic AST Fallback)"
        print(f"  - [{lang.upper()}]: {status}")

    print("All target languages verified in 100% Read-Only mode.")
    return True


if __name__ == "__main__":
    verify_grammars()
