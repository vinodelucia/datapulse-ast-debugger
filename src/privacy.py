"""Redação de dados sensíveis (PII, caminhos locais e segredos) e scanner de credenciais.

Catálogo de padrões de segredos adaptado de elementalsouls/Claude-BugHunter (MIT).
Usado antes de persistir em memória local, enviar ao LLM (opt-in) ou montar telemetria global.
"""

import re
from typing import Dict, List, Tuple

# Ordem importa: padrões específicos de provedores vêm antes dos genéricos.
SECRET_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    ("AWS_ACCESS_KEY", "CRITICAL", "[REDACTED_AWS_KEY]", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GCP_SERVICE_ACCOUNT", "CRITICAL", '"type": "[REDACTED_GCP_SA]"', re.compile(r'"type"\s*:\s*"service_account"')),
    ("GOOGLE_API_KEY", "HIGH", "[REDACTED_GOOGLE_KEY]", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GH_PAT_FINEGRAINED", "CRITICAL", "[REDACTED_GITHUB_TOKEN]", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("GH_TOKEN", "CRITICAL", "[REDACTED_GITHUB_TOKEN]", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("ANTHROPIC_API", "CRITICAL", "[REDACTED_API_KEY]", re.compile(r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{40,}\b")),
    ("OPENAI_PROJECT", "CRITICAL", "[REDACTED_API_KEY]", re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b")),
    ("OPENAI_LEGACY", "CRITICAL", "[REDACTED_API_KEY]", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("STRIPE_KEY", "CRITICAL", "[REDACTED_API_KEY]", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_\w{8,}\b")),
    ("HUGGINGFACE_TOKEN", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("SLACK_TOKEN", "HIGH", "[REDACTED_SLACK_TOKEN]", re.compile(r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b")),
    (
        "SLACK_WEBHOOK",
        "MEDIUM",
        "[REDACTED_WEBHOOK]",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    ("SENDGRID_KEY", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("MAILGUN_KEY", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("TWILIO_API", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("TWILIO_SID", "MEDIUM", "[REDACTED_API_KEY]", re.compile(r"\bAC[0-9a-f]{32}\b")),
    ("DIGITALOCEAN_TOKEN", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    ("NPM_TOKEN", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PYPI_TOKEN", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b")),
    ("DOCKER_HUB_PAT", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b")),
    ("LINEAR_API", "MEDIUM", "[REDACTED_API_KEY]", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("NEWRELIC_LICENSE", "MEDIUM", "[REDACTED_API_KEY]", re.compile(r"\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b")),
    ("NGROK_AUTH", "MEDIUM", "[REDACTED_API_KEY]", re.compile(r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b")),
    ("DISCORD_BOT", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b")),
    ("TELEGRAM_BOT", "HIGH", "[REDACTED_API_KEY]", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("JWT", "MEDIUM", "[REDACTED_JWT]", re.compile(r"\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}\b")),
    (
        "PRIVATE_KEY_HEADER",
        "CRITICAL",
        "[REDACTED_PRIVATE_KEY]",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    (
        "BASIC_AUTH_URL",
        "HIGH",
        "https://[REDACTED_CREDENTIALS]@",
        re.compile(r"https?://[^/\s:@]{1,64}:[^/\s:@]{1,64}@"),
    ),
]

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
    *[(pattern, replacement) for _name, _sev, replacement, pattern in SECRET_PATTERNS],
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


def scan_secrets(text: str) -> List[Dict[str, str]]:
    """Identifica segredos conhecidos em um bloco de texto (sem retornar o valor completo)."""
    hits: List[Dict[str, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, _repl, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                hits.append(
                    {
                        "pattern": name,
                        "severity": sev,
                        "line": str(line_no),
                        "preview": match.group(0)[:8] + "...",
                    }
                )
    return hits


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
