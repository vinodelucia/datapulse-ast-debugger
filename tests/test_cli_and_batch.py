import json
import logging
import tempfile
from pathlib import Path
from types import SimpleNamespace

import cli_audit
from src.analyzer_agent import DataPulseAnalyzerAgent
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser


def test_cli_audit_json_and_markdown_outputs(capsys):
    sample_dir = Path(__file__).parent / "sample_code"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as mem_dir:
        exit_code = cli_audit.run_cli_audit(
            target_path=str(sample_dir / "insecure_server.js"),
            languages=["javascript"],
            memory_dir=mem_dir,
            output_format="json",
            fast_embeddings=True,
        )
        assert exit_code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["mode"] == "100% Read-Only"
        assert payload["issues_found"] >= 7

        exit_md = cli_audit.run_cli_audit(
            target_path=str(sample_dir / "unindexed_report.sql"),
            languages=["sql"],
            memory_dir=mem_dir,
            output_format="markdown",
            fast_embeddings=True,
        )
        assert exit_md == 0
        md_out = capsys.readouterr().out
        assert "Relatório DataPulse AST Debugger" in md_out
        assert "SQL_FullTableScan" in md_out


def test_cli_audit_missing_target_returns_1():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as mem_dir:
        code = cli_audit.run_cli_audit(
            target_path="C:/non_existent_path_datapulse_12345",
            languages=["python"],
            memory_dir=mem_dir,
            fast_embeddings=True,
        )
        assert code == 1


def test_batch_save_and_clear_memory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        memory = LocalDiagnosticMemory(persist_dir=tmp, use_sentence_transformers=False)
        records = [
            DiagnosticRecord(
                file_path=f"src/mod_{i}.py",
                language="python",
                access_point_id=f"python:src/mod_{i}.py:fn_{i}:L1-L5",
                ast_hash=f"{i}" * 64,
                severity="HIGH",
                error_category="Pandas_Iterrows_Bottleneck",
                diagnostic_summary="summary",
                original_code="for _, r in df.iterrows(): pass",
                suggested_fix="df['x'] = 1",
            )
            for i in range(3)
        ]
        counts = memory.save_diagnostics_batch(records)
        assert all(v == 1 for v in counts.values())
        assert len(memory.get_all_diagnostics()) == 3

        counts_second = memory.save_diagnostics_batch(records)
        assert all(v == 2 for v in counts_second.values())

        cleared = memory.clear_memory()
        assert cleared == 3
        assert memory.get_all_diagnostics() == []


def test_llm_opt_in_redacts_secrets_and_logs_on_failure(caplog, tmp_path):
    target_file = tmp_path / "svc.py"
    target_file.write_text("def run():\n    api_key = 'secret-value-9999'\n    return api_key\n")
    ap = MultiLangASTParser().parse_file_readonly(str(target_file))[0]

    captured_prompts = []

    class FakeModels:
        def generate_content(self, model, contents, config):
            captured_prompts.append(contents)
            return SimpleNamespace(
                text=json.dumps(
                    {
                        "has_issue": True,
                        "severity": "HIGH",
                        "error_category": "Hardcoded_Secret",
                        "chain_of_thought": "checked",
                        "diagnostic_summary": "secret found",
                        "suggested_fix": "use env",
                    }
                )
            )

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as mem_dir:
        memory = LocalDiagnosticMemory(persist_dir=mem_dir, use_sentence_transformers=False)
        agent = DataPulseAnalyzerAgent(memory=memory, allow_llm=True, api_key="fake")
        agent.client = SimpleNamespace(models=FakeModels())

        rec = agent.analyze_access_point(ap, persist_to_memory=False)
        assert rec is not None
        assert rec.error_category == "Hardcoded_Secret"
        assert "secret-value-9999" not in captured_prompts[0]
        assert "[REDACTED_SECRET]" in captured_prompts[0]

        # Test fallback + warning log when LLM raises
        class FailingModels:
            def generate_content(self, **kwargs):
                raise RuntimeError("quota exceeded")

        agent.client = SimpleNamespace(models=FailingModels())
        with caplog.at_level(logging.WARNING):
            agent.analyze_access_point(ap, persist_to_memory=False)
        assert "Falha na análise via LLM" in caplog.text
