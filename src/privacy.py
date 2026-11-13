"""Redação de dados sensíveis (PII, caminhos locais e segredos) usada antes de persistir,
enviar ao LLM (opt-in) ou montar o payload de telemetria global."""

import re
from typing import List, Tuple

_REDACTIONS: List[Tuple[re.Pattern, str]] = [
    # Atribuição de credenciais com valor literal entre aspas (mantém o nome da variável)
    (
        re.compile(
            r"""(?ix)
            (\b\w*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\w*\b
             \s*[:=]\s*)(['"])[^'"\s]{4,}\2
            """
        ),
        r"\1\2[REDACTED_SECRET]\2",
    ),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_\w{8,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bgh[pousr]_\w{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bBearer\s+[\w.\-~+/]{16,}=*", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    # E-mails
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[REDACTED_EMAIL]"),
    # Caminhos: Windows, UNC, POSIX comuns e ~/
    (re.compile(r"[A-Za-z]:\\[^\s'\"`<>|]+"), "[REDACTED_PATH]"),
    (re.compile(r"\\\\[\w.$-]+\\[^\s'\"`<>|]+"), "[REDACTED_PATH]"),
    (
        re.compile(r"(?<![\w:/.])/(?:home|Users|root|var|etc|opt|tmp|mnt|srv|usr)/[^\s'\"`<>|]+"),
        "[REDACTED_PATH]",
    ),
    (re.compile(r"(?<![\w.])~/[^\s'\"`<>|]+"), "[REDACTED_PATH]"),
    # IPs
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"), "[REDACTED_IP]"),
]

_CATEGORY_RE = re.compile(r"[^A-Za-z0-9_]")


def redact_sensitive(text: str) -> str:
    """Aplica todas as regras de redação (não destrutivo para o resto do texto)."""
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_category(category: str) -> str:
    """Normaliza error_category para `[A-Za-z0-9_]{1,64}` (impede texto livre/código na telemetria)."""
    cleaned = _CATEGORY_RE.sub("_", category or "")[:64].strip("_")
    return cleaned or "Unknown"


def sanitize_summary(summary: str, max_len: int = 500) -> str:
    """Redige PII e limita o tamanho do resumo livre enviado na telemetria."""
    return redact_sensitive(summary or "")[:max_len]
