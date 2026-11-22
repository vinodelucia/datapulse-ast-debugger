"""Leak-Guard: verifica em modo Read-Only se nenhum segredo real foi commitado no repositório."""

import os
import sys
from pathlib import Path
from typing import Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.privacy import scan_secrets

IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".datapulse_memory", ".pytest_cache", "dist", "build",
}
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sql", ".r", ".R", ".yml", ".yaml", ".json", ".toml", ".md", ".env",
}


def scan_repository_for_leaks(root_path: Path = ROOT_DIR) -> List[Dict[str, str]]:
    """Varre arquivos versionáveis em busca de tokens/chaves reais usando src.privacy.scan_secrets."""
    leaks: List[Dict[str, str]] = []
    for dirpath, dirs, files in os.walk(root_path):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        for name in sorted(files):
            fp = Path(dirpath) / name
            if fp.suffix not in ALLOWED_EXTENSIONS and name != ".env":
                continue
            if fp.stat().st_size > 1_000_000:
                continue
            text = fp.read_text(encoding="utf-8", errors="replace")
            for hit in scan_secrets(text):
                leaks.append({**hit, "file": str(fp.relative_to(root_path)).replace("\\", "/")})
    return leaks


def main() -> int:
    leaks = scan_repository_for_leaks()
    if not leaks:
        print("Leak-Guard OK: nenhum segredo ou token de provedor detectado no repositório.")
        return 0
    print(f"Leak-Guard FALHOU: {len(leaks)} possível(is) segredo(s) detectado(s):", file=sys.stderr)
    for item in leaks:
        print(
            f"  - [{item['severity']}] {item['file']}:{item['line']} ({item['pattern']}: {item['preview']})",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
