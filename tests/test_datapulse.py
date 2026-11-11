import tempfile
from pathlib import Path

from src.analyzer_agent import DataPulseAnalyzerAgent
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser


def test_multilang_ast_parser_readonly():
    parser = MultiLangASTParser()
    sample_dir = Path(__file__).parent / "sample_code"

    py_points = parser.parse_file_readonly(str(sample_dir / "sales_pipeline.py"))
    sql_points = parser.parse_file_readonly(str(sample_dir / "unindexed_report.sql"))
    r_points = parser.parse_file_readonly(str(sample_dir / "vectorization_bottleneck.R"))

    assert len(py_points) >= 3
    assert any(ap.name == "process_sales_chunk" for ap in py_points)
    assert len(sql_points) >= 1
    assert len(r_points) >= 1
    assert all(len(ap.ast_hash) == 64 for ap in py_points + sql_points + r_points)


def test_local_diagnostic_memory_and_privacy_sanitizer():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        memory = LocalDiagnosticMemory(
            persist_dir=tmp_dir,
            use_sentence_transformers=False,
        )

        rec = DiagnosticRecord(
            file_path="C:\\secret_project\\src\\etl\\loader.py",
            language="python",
            access_point_id="python:loader.py:transform:L10-L25",
            ast_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            severity="HIGH",
            error_category="Pandas_Iterrows_Bottleneck",
            diagnostic_summary="Erro detectado em C:\\secret_project\\src\\etl\\loader.py no servidor 192.168.1.50.",
            original_code="for idx, row in secret_df.iterrows(): pass",
            suggested_fix="secret_df['col'] = 1",
        )

        # Primeira gravação -> recorrência 1
        rec_count_1 = memory.save_diagnostic(rec)
        assert rec_count_1 == 1

        # Segunda gravação do mesmo ponto de acesso -> recorrência 2
        rec_count_2 = memory.save_diagnostic(rec)
        assert rec_count_2 == 2

        # Busca RAG similar
        matches = memory.retrieve_similar_past_issues("df.iterrows()", language="python", top_k=2)
        assert len(matches) == 1
        assert matches[0]["metadata"]["recurrence_count"] == 2

        # Verifica sanitização de código-fonte e PII no payload global
        payload = memory.prepare_anonymized_global_payload([rec.access_point_id])
        assert payload["client_version"] == "1.0.0"
        contrib = payload["contributions"][0]
        assert "secret_df" not in str(payload)
        assert "192.168.1.50" not in contrib["abstract_diagnostic"]
        assert "original_code" not in contrib


def test_analyzer_agent_end_to_end():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        memory = LocalDiagnosticMemory(
            persist_dir=tmp_dir,
            use_sentence_transformers=False,
        )
        parser = MultiLangASTParser()
        agent = DataPulseAnalyzerAgent(memory=memory, parser=parser, api_key=None)

        sample_dir = Path(__file__).parent / "sample_code"
        diagnostics = agent.scan_directory(str(sample_dir))

        assert len(diagnostics) >= 4
        categories = {d.error_category for d in diagnostics}
        assert "Pandas_Iterrows_Bottleneck" in categories
        assert "SQL_FullTableScan" in categories
        assert "R_Vectorization_Missing" in categories
