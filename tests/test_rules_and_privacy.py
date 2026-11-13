import tempfile
from pathlib import Path

import pytest
import requests

from src import memory_store
from src.analyzer_agent import DataPulseAnalyzerAgent
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser
from src.privacy import redact_sensitive, sanitize_category, sanitize_summary
from src.rules import evaluate


def category(lang: str, code: str):
    rule = evaluate(lang, code)
    return rule.category if rule else None


# ------------------------------------------------------------------ privacidade
def test_redaction_covers_paths_emails_tokens_and_keeps_context():
    text = (
        "Falha em /home/vini/projeto/etl.py e C:\\Users\\vini\\x.py, contato vini@example.com, "
        "host 10.0.0.5 e ::1:2:3:4, password = 'hunter2hunter2'. Fim do diagnóstico útil."
    )
    out = redact_sensitive(text)
    for leaked in ("/home/vini", "C:\\Users", "vini@example.com", "10.0.0.5", "hunter2hunter2"):
        assert leaked not in out
    assert "Fim do diagnóstico útil." in out  # regex não-gulosa preserva o restante
    assert "password = '[REDACTED_SECRET]'" in out


def test_sanitize_category_and_summary_limits():
    assert sanitize_category("Bad Category; rm -rf /") == "Bad_Category__rm__rf"
    assert len(sanitize_summary("x" * 5000)) == 500
    assert "AKIAABCDEFGHIJKLMNOP" not in sanitize_summary("chave AKIAABCDEFGHIJKLMNOP vazou")


def test_secrets_are_redacted_before_persisting_in_memory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        memory = LocalDiagnosticMemory(persist_dir=tmp, use_sentence_transformers=False)
        memory.save_diagnostic(
            DiagnosticRecord(
                file_path="a.js", language="javascript", access_point_id="javascript:a.js:f:L1-L2",
                ast_hash="h" * 64, severity="HIGH", error_category="JS_Hardcoded_Secret",
                diagnostic_summary="segredo", original_code="const apiKey = 'abcd1234efgh5678';",
                suggested_fix="x",
            )
        )
        stored = memory.get_all_diagnostics()[0]["original_code"]
        assert "abcd1234efgh5678" not in stored


def test_telemetry_reports_failure_honestly(monkeypatch):
    class Resp:
        status_code = 500

        def raise_for_status(self):
            raise requests.HTTPError("500")

    monkeypatch.setattr(memory_store.requests, "post", lambda *a, **k: Resp())
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        memory = LocalDiagnosticMemory(persist_dir=tmp, use_sentence_transformers=False)
        assert memory.submit_opt_in_telemetry([])["status"] == "failed"


# --------------------------------------------------------------------- regras
def test_no_false_positives_on_lookalikes():
    assert category("javascript", "function f(s){ return regex.exec(s + 'x'); }") is None
    assert category("javascript", "const v = obj.eval(1); // eval(x)") is None
    assert category("python", 'def f():\n    msg = "df.iterrows() is slow"\n    return msg') is None
    assert category("python", "def f(x):\n    # for row in df.iterrows(): pass\n    return transform(x)") is None
    assert category("r", "f <- function(x) { platform(x) + inform(x) }") is None
    assert category("javascript", "const t = { token: 'xxxxxxxxxxxx' };") is None  # placeholder
    # promise devolvida ao chamador (return) é tratada por quem chama: sem alerta
    assert category("javascript", "function f(){ return p.then((x) => x); }") is None
    # promise "solta" sem catch: alerta
    assert category("javascript", "function f(){ p.then((x) => x); }") == "JS_Unhandled_Promise_Rejection"


def test_true_positives_and_precedence():
    assert category("python", "def f():\n    try:\n        x()\n    except Exception as e:\n        pass") == "Silent_Exception_Swallowing"
    assert category("python", "def f(df):\n    return df.apply(lambda r: r.a, axis=1)") == "Pandas_Apply_Axis1_Slow"
    assert category("python", "def f(parts):\n    out = pd.DataFrame()\n    for p in parts:\n        out = pd.concat([out, p])\n    return out") == "Pandas_Concat_In_Loop"
    assert category("sql", "DELETE FROM users;") == "SQL_Mutation_Without_Where"
    assert category("sql", "DELETE FROM users WHERE id = 1;") is None
    assert category("sql", "SELECT a FROM t WHERE id NOT IN (SELECT id FROM u)") == "SQL_NotIn_Subquery"
    assert category("javascript", "async function f(xs){ for (const x of xs) { await g(x); } }") == "JS_Await_In_Loop"
    assert category("javascript", "async function f(s){ for await (const x of s) { await g(x); } }") is None
    assert category("r", "f <- function(n){ for (i in 1:n) { out <- c(out, i) } }") == "R_Vectorization_Missing"
    # maior severidade vence (SQLi CRITICAL > iterrows HIGH), independente da ordem
    mixed = (
        "def f(df, cur, uid):\n    for _, r in df.iterrows():\n        pass\n"
        "    cur.execute(f\"SELECT * FROM t WHERE id = '{uid}'\")"
    )
    assert category("python", mixed) == "SQL_Injection_Vulnerability"


def test_ignore_marker_suppresses_findings():
    assert category("javascript", "function f(x){ return eval(x); } // datapulse: ignore") is None


# ----------------------------------------------------------------------- parser
def test_class_methods_not_duplicated_and_uppercase_extension(tmp_path):
    src = "class A:\n    def m1(self):\n        return 1\n    def m2(self):\n        return 2\n"
    (tmp_path / "MODULE.PY").write_text(src)
    points = MultiLangASTParser().parse_directory_readonly(str(tmp_path))
    assert sorted(ap.name for ap in points) == ["m1", "m2"]


def test_ast_hash_is_structural_and_leaks_no_text(tmp_path):
    (tmp_path / "a.py").write_text("def secret_func(token_value):\n    return token_value + 'abc'\n")
    (tmp_path / "b.py").write_text("def other_name(zzz):\n    return zzz + 'xyz'\n")
    parser = MultiLangASTParser()
    a = parser.parse_file_readonly(str(tmp_path / "a.py"))[0]
    b = parser.parse_file_readonly(str(tmp_path / "b.py"))[0]
    assert a.ast_hash == b.ast_hash
    assert "secret_func" not in a.ast_sexp and "token_value" not in a.ast_sexp


def test_access_id_disambiguates_same_filename_in_different_folders(tmp_path):
    for folder in ("pkg_a", "pkg_b"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "utils.py").write_text("def f():\n    return 1\n")
    ids = {ap.access_id for ap in MultiLangASTParser().parse_directory_readonly(str(tmp_path))}
    assert len(ids) == 2


# ------------------------------------------------------------------ reincidência
def test_recurrence_requires_same_hash_not_just_any_neighbour(tmp_path):
    (tmp_path / "x.js").write_text("function a(){ return eval(p); }\n")
    (tmp_path / "y.js").write_text("function b(){ return eval(q) + 1; }\n")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        memory = LocalDiagnosticMemory(persist_dir=tmp, use_sentence_transformers=False)
        parser = MultiLangASTParser()
        agent = DataPulseAnalyzerAgent(memory=memory, parser=parser, api_key=None)
        a = parser.parse_file_readonly(str(tmp_path / "x.js"))[0]
        b = parser.parse_file_readonly(str(tmp_path / "y.js"))[0]
        first = agent.analyze_access_point(a)
        assert "Reincidência" not in first.diagnostic_summary
        other = agent.analyze_access_point(b)  # vizinho diferente: modo fast não é semântico
        assert "Reincidência" not in other.diagnostic_summary
        again = agent.analyze_access_point(a)  # mesmo ast_hash: reincidência real
        assert "Reincidência" in again.diagnostic_summary


def test_llm_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key-for-test")
    monkeypatch.delenv("DATAPULSE_ALLOW_LLM", raising=False)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        memory = LocalDiagnosticMemory(persist_dir=tmp, use_sentence_transformers=False)
        assert DataPulseAnalyzerAgent(memory=memory).client is None


def test_rules_have_no_catastrophic_backtracking():
    import time

    hostile = {
        "python": "for x in y:\n" + "    a = 1\n" * 3000,
        "sql": "SELECT " + "a, " * 5000 + "b FROM t WHERE " + "x = 1 AND " * 3000,
        "javascript": "function f(){ " + "(a+" * 500 + " }",
        "r": "f <- function(){ " + "for (i in x) " * 2000 + " }",
    }
    for lang, code in hostile.items():
        start = time.perf_counter()
        evaluate(lang, code)
        assert time.perf_counter() - start < 1.0, f"regra lenta para {lang}"
