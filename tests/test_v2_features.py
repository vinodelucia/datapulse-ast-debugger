import json
import tempfile
from pathlib import Path

import cli_audit
from src.analyzer_agent import DataPulseAnalyzerAgent
from src.config import DataPulseConfig
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser
from src.rules import evaluate, evaluate_all
from src.sarif_exporter import SARIF_SCHEMA, build_sarif_report


def test_sqlglot_multidialect_and_new_sql_rules():
    sample_sql = Path(__file__).parent / "sample_code" / "advanced_queries.sql"
    points = MultiLangASTParser().parse_file_readonly(str(sample_sql), sql_dialect="postgres")
    assert len(points) == 4
    cats = [evaluate("sql", ap.code_snippet).category for ap in points]
    assert "SQL_Mutation_Without_Where" in cats
    assert "SQL_Distinct_With_Join" in cats
    assert "SQL_Union_Without_All" in cats
    assert "SQL_NonSargable_Predicate" in cats

    # Cartesian JOIN without ON/USING and NOT IN subquery
    assert evaluate("sql", "SELECT a.id FROM a JOIN b;").category == "SQL_Cartesian_Join_Missing_On"
    assert evaluate("sql", "SELECT a.id FROM a WHERE a.id NOT IN (SELECT id FROM b);").category == "SQL_NotIn_Subquery"
    # UNION ALL is clean
    assert evaluate("sql", "SELECT id FROM t1 UNION ALL SELECT id FROM t2;") is None


def test_python_ast_rules_and_non_false_positives():
    sample_py = Path(__file__).parent / "sample_code" / "spark_polars_pipeline.py"
    points = MultiLangASTParser().parse_file_readonly(str(sample_py))
    by_name = {ap.name: evaluate("python", ap.code_snippet).category for ap in points}
    assert by_name["collect_all_driver_oom"] == "PySpark_Collect_Driver_OOM"
    assert by_name["apply_python_udf"] == "PySpark_Python_UDF_Overhead"
    assert by_name["iterate_polars_rows"] == "Polars_Row_Iteration_Bottleneck"
    assert by_name["deserialize_untrusted"] == "Python_Insecure_Deserialization"
    assert by_name["append_audit_item"] == "Python_Mutable_Default_Arg"

    assert evaluate("python", "def f(x):\n    return eval(x)").category == "Python_Eval_Exec_Injection"
    assert evaluate("python", "def f():\n    api_token = 'super-real-credential-9999'\n    return api_token").category == "Python_Hardcoded_Secret"

    # Non-false-positives
    assert evaluate("python", "def f():\n    import gc\n    return gc.collect()") is None
    assert evaluate("python", "def f(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)") is None
    assert evaluate("python", 'def f():\n    return "eval(x) and pickle.loads(y)"') is None
    assert evaluate("python", "def f(df):\n    return df.limit(10).collect()") is None


def test_r_and_js_v2_ast_rules():
    assert evaluate("r", "f <- function(x) { mean(x, na.rm = T) }").category == "R_T_F_Symbol_Usage"
    assert evaluate("r", "f <- function(df) { attach(df) }").category == "R_Attach_Namespace_Pollution"
    assert evaluate("r", "f <- function(x) { sapply(x, sum) }").category == "R_Sapply_Type_Unsafe"

    assert evaluate("javascript", "function merge(obj, a, b, v) { obj[a][b] = v; }").category == "JS_Prototype_Pollution"
    assert evaluate("javascript", "function safe(obj, a, b, v) { if (a === '__proto__') return; obj[a][b] = v; }") is None
    assert evaluate("javascript", "function proxy(req) { return fetch(req.query.url); }").category == "JS_SSRF_Dynamic_Fetch"
    assert evaluate("javascript", "function parse(raw) { return JSON.parse(raw); }").category == "JS_Unsafe_JSON_Parse"
    assert evaluate("javascript", "function parseOk(raw) { try { return JSON.parse(raw); } catch (e) { return null; } }") is None


def test_multi_finding_per_access_point_and_batch_upsert(tmp_path):
    code = (
        "def risky(df, raw, items=[]):\n"
        "    x = eval(raw)\n"
        "    for _, r in df.iterrows():\n"
        "        pass\n"
        "    return x\n"
    )
    matches = evaluate_all("python", code)
    cats = [m.rule.category for m in matches]
    assert "Python_Eval_Exec_Injection" in cats
    assert "Pandas_Iterrows_Bottleneck" in cats
    assert "Python_Mutable_Default_Arg" in cats

    f = tmp_path / "multi.py"
    f.write_text(code)
    ap = MultiLangASTParser().parse_file_readonly(str(f))[0]

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as mem_dir:
        memory = LocalDiagnosticMemory(persist_dir=mem_dir, use_sentence_transformers=False)
        agent = DataPulseAnalyzerAgent(memory=memory)
        recs = agent.analyze_access_point_all(ap, persist_to_memory=True)
        assert len(recs) >= 3
        stored = memory.get_all_diagnostics()
        assert len(stored) == len(recs)


def test_cyclomatic_complexity_and_health_score(tmp_path):
    branches = "\n".join(f"    if x == {i}:\n        pass" for i in range(15))
    f = tmp_path / "complex.py"
    f.write_text(f"def branchy(x):\n{branches}\n    return x\n")
    ap = MultiLangASTParser().parse_file_readonly(str(f))[0]
    assert ap.cyclomatic_complexity >= 16

    matches = evaluate_all("python", ap.code_snippet, complexity_threshold=12, cyclomatic_complexity=ap.cyclomatic_complexity)
    assert any(m.rule.category == "High_Cyclomatic_Complexity" for m in matches)

    rec = DiagnosticRecord(
        file_path=str(f), language="python", access_point_id=ap.access_id,
        ast_hash=ap.ast_hash, severity="CRITICAL", error_category="Python_Eval_Exec_Injection",
        diagnostic_summary="bad", original_code="eval(x)", suggested_fix="ast.literal_eval(x)",
    )
    health = DataPulseAnalyzerAgent.compute_health_score(2, [rec], avg_complexity=float(ap.cyclomatic_complexity))
    assert 0 <= health["score"] < 100
    assert health["grade"] in ("A", "B", "C", "D", "F")
    assert health["by_severity"]["CRITICAL"] == 1


def test_sarif_2_1_0_compliance():
    rec = DiagnosticRecord(
        file_path="C:/repo/src/etl.py",
        language="python",
        access_point_id="python:src/etl.py:run:L10-L15",
        ast_hash="a" * 64,
        severity="CRITICAL",
        error_category="Python_Eval_Exec_Injection",
        diagnostic_summary="eval detected",
        original_code="eval(x)",
        suggested_fix="ast.literal_eval(x)",
        start_line=10,
        end_line=15,
    )
    sarif = build_sarif_report([rec], tool_version="2.0.0", base_dir="C:/repo")
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    res = run["results"][0]
    assert rules[0]["id"] == "Python_Eval_Exec_Injection"
    assert rules[0]["properties"]["security-severity"] == "9.5"
    assert res["ruleId"] == "Python_Eval_Exec_Injection"
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/etl.py"
    assert loc["region"]["startLine"] == 10
    assert "datapulseAstHash/v1" in res["partialFingerprints"]


def test_datapulse_config_yaml_and_cli_gates(tmp_path):
    (tmp_path / ".datapulse.yml").write_text(
        "min_severity: HIGH\ndisable_rules:\n  - Pandas_Iterrows_Bottleneck\nignore_paths:\n  - ignored_dir\n",
        encoding="utf-8",
    )
    (tmp_path / "ignored_dir").mkdir()
    (tmp_path / "ignored_dir" / "bad.py").write_text("def g(x):\n    return eval(x)\n")
    (tmp_path / "app.py").write_text(
        "def f(df, x):\n    for _, r in df.iterrows():\n        pass\n    return eval(x)\n"
    )
    cfg = DataPulseConfig.load(tmp_path)
    assert cfg.min_severity == "HIGH"
    assert "Pandas_Iterrows_Bottleneck" in cfg.disable_rules

    sarif_out = tmp_path / "out.sarif"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as mem_dir:
        exit_code = cli_audit.run_cli_audit(
            target_path=str(tmp_path),
            languages=["python"],
            memory_dir=mem_dir,
            output_format="sarif",
            fast_embeddings=True,
            output_file=str(sarif_out),
            fail_on="HIGH",
        )
        assert exit_code == 2
        data = json.loads(sarif_out.read_text(encoding="utf-8"))
        rule_ids = {r["ruleId"] for r in data["runs"][0]["results"]}
        assert rule_ids == {"Python_Eval_Exec_Injection"}

        # Incremental second run skips unchanged app.py -> 0 findings, exit code 0
        exit_inc = cli_audit.run_cli_audit(
            target_path=str(tmp_path),
            languages=["python"],
            memory_dir=mem_dir,
            output_format="json",
            fast_embeddings=True,
            fail_on="HIGH",
            incremental=True,
        )
        assert exit_inc == 0


def test_retrieve_similar_batch():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as mem_dir:
        memory = LocalDiagnosticMemory(persist_dir=mem_dir, use_sentence_transformers=False)
        rec = DiagnosticRecord(
            file_path="a.py", language="python", access_point_id="python:a.py:f:L1-L2",
            ast_hash="b" * 64, severity="HIGH", error_category="Pandas_Iterrows_Bottleneck",
            diagnostic_summary="summary", original_code="for _, r in df.iterrows(): pass",
            suggested_fix="df['a'] = 1",
        )
        memory.save_diagnostics_batch([rec])
        res = memory.retrieve_similar_batch(
            [("for _, r in df.iterrows(): pass", "python"), ("SELECT 1", "sql")],
            top_k=2,
        )
        assert len(res) == 2
        assert len(res[0]) == 1
        assert res[1] == []
