import json
import sys
from pathlib import Path

# Ensure project root is on sys.path when running `streamlit run dashboard/app.py`
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import plotly.express as px
import streamlit as st

from src.analyzer_agent import DataPulseAnalyzerAgent
from src.memory_store import DiagnosticRecord, LocalDiagnosticMemory
from src.parser_engine import MultiLangASTParser

st.set_page_config(
    page_title="DataPulse AST Debugger",
    page_icon="🛡️",
    layout="wide",
)

# Enforce tabular-nums on KPIs and clean spacing without decorative bloat
st.markdown(
    """
    <style>
    [data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; }
    </style>
    """,
    unsafe_allow_html=True,
)

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

I18N = {
    "en": {
        "mode_caption": "Mode: **100% Read-Only & Local Memory**",
        "target_dir": "Target Project Directory:",
        "monitored_langs": "Monitored Languages:",
        "severity_filter": "Filter by Severity:",
        "allow_llm": "Enable Gemini LLM (Opt-In, redacted)",
        "allow_llm_help": "Off by default. When enabled and GEMINI_API_KEY is set, sends PII-redacted AST blocks to Gemini.",
        "scan_btn": "🔍 Map AST & Diagnose",
        "scan_toast": "Scanning AST in Read-Only mode...",
        "scan_demo_saved": "No issues found in target; sample diagnostic saved to .datapulse_memory!",
        "scan_count_saved": "{count} access point(s) diagnosed and saved to .datapulse_memory!",
        "exit_btn": "🚪 End Session / Close Report",
        "clear_expander": "🧹 Local Memory Maintenance",
        "clear_confirm": "Confirm clearing all local diagnostics",
        "clear_btn": "Clear .datapulse_memory",
        "clear_done": "Removed {count} record(s) from local memory.",
        "modal_title": "### 🤝 Optional Contribution to Global Solutions Knowledge Base",
        "modal_body": (
            "Your diagnostic session is ending. All data remains **exclusively on your machine**.\n"
            "Would you like to help the community by sending **only anonymized metadata** "
            "(AST hashes and error categories) of the issues discovered today?\n\n"
            "*🔒 **Privacy Guarantee:** Your source code, file paths, and variable names are **never** transmitted.*"
        ),
        "inspect_json": "👁️ Inspect exact JSON payload to be sent (Transparent Audit)",
        "btn_authorize": "✅ Authorize & Send Anonymized Metadata",
        "msg_sent": "Thank you! Error signatures shared successfully. You may now close this tab.",
        "msg_failed": "Could not reach telemetry endpoint (saved locally only).",
        "btn_offline": "❌ Do Not Send (Keep 100% Offline)",
        "msg_offline": "Session closed without external transmission. Local memory preserved.",
        "header": "📊 AST Diagnostic Report & Access Points",
        "empty_info": "No diagnostics in local memory yet. Set a target directory and click **Map AST & Diagnose** in the sidebar.",
        "empty_filter": "No diagnostics match the selected language/severity filters.",
        "kpi_mapped": "Mapped Access Points",
        "kpi_critical": "Critical / High Alerts",
        "kpi_recurrence": "Memory Recurrences",
        "kpi_status": "Repository Status",
        "kpi_status_val": "Read-Only Safe 🔒",
        "export_md": "⬇️ Export Markdown",
        "export_json": "⬇️ Export JSON",
        "chart_heatmap": "Incidence & Recurrence by File",
        "chart_pie": "Diagnostics by Language (Python, SQL, R, JS/TS)",
        "inspector_title": "🔬 Side-by-Side Access Point Inspector",
        "recurrence_label": "Recurrence",
        "ai_diag": "**Diagnostic:**",
        "ast_caption": "AST Structural Hash: `{ast_hash}` | Last analyzed: `{timestamp}`",
        "orig_code": "❌ **Detected Original Code (Read-Only):**",
        "fix_code": "✅ **Suggested Refactoring (Not Auto-Applied):**",
    },
    "pt": {
        "mode_caption": "Modo: **100% Read-Only & Local Memory**",
        "target_dir": "Diretório do Projeto Alvo:",
        "monitored_langs": "Linguagens Monitoradas:",
        "severity_filter": "Filtrar por Severidade:",
        "allow_llm": "Habilitar Gemini LLM (Opt-In, redigido)",
        "allow_llm_help": "Desligado por padrão. Quando ativo com GEMINI_API_KEY, envia blocos com segredos/PII redigidos ao Gemini.",
        "scan_btn": "🔍 Mapear AST & Diagnosticar",
        "scan_toast": "Escaneando AST em modo Read-Only...",
        "scan_demo_saved": "Nenhum problema no alvo; diagnóstico de exemplo salvo em .datapulse_memory!",
        "scan_count_saved": "{count} ponto(s) de acesso diagnosticado(s) e salvo(s) em .datapulse_memory!",
        "exit_btn": "🚪 Encerrar Sessão / Fechar Relatório",
        "clear_expander": "🧹 Manutenção da Memória Local",
        "clear_confirm": "Confirmar limpeza dos diagnósticos locais",
        "clear_btn": "Limpar .datapulse_memory",
        "clear_done": "{count} registro(s) removido(s) da memória local.",
        "modal_title": "### 🤝 Contribuição Opcional para o Banco Global de Soluções",
        "modal_body": (
            "Sua sessão de diagnóstico está sendo encerrada. Todos os dados permanecem **exclusivamente na sua máquina**.\n"
            "Deseja ajudar a comunidade enviando **apenas os metadados anonimizados** "
            "(hashes de AST e categorias de erro) dos problemas descobertos hoje?\n\n"
            "*🔒 **Garantia de Privacidade:** Seu código-fonte, nomes de arquivos e variáveis **jamais** são transmitidos.*"
        ),
        "inspect_json": "👁️ Inspecionar exatamente o JSON que será enviado (Auditoria Transparente)",
        "btn_authorize": "✅ Autorizar e Enviar Metadados Anonimizados",
        "msg_sent": "Obrigado! Assinaturas de erro compartilhadas com sucesso. Você já pode fechar a aba.",
        "msg_failed": "Não foi possível contatar o servidor de telemetria (mantido apenas localmente).",
        "btn_offline": "❌ Não Enviar (Manter 100% Offline)",
        "msg_offline": "Sessão encerrada sem envio externo. Memória local preservada.",
        "header": "📊 Relatório de Diagnóstico & Pontos de Acesso AST",
        "empty_info": "Nenhum diagnóstico na memória local ainda. Defina o diretório alvo e clique em **Mapear AST & Diagnosticar** na barra lateral.",
        "empty_filter": "Nenhum diagnóstico corresponde aos filtros de linguagem/severidade selecionados.",
        "kpi_mapped": "Pontos de Acesso Mapeados",
        "kpi_critical": "Alertas Críticos / Altos",
        "kpi_recurrence": "Reincidências na Memória",
        "kpi_status": "Status do Repositório",
        "kpi_status_val": "Read-Only Seguro 🔒",
        "export_md": "⬇️ Exportar Markdown",
        "export_json": "⬇️ Exportar JSON",
        "chart_heatmap": "Incidência e Recorrência por Arquivo",
        "chart_pie": "Diagnósticos por Linguagem (Python, SQL, R, JS/TS)",
        "inspector_title": "🔬 Inspetor de Pontos de Acesso (Lado a Lado)",
        "recurrence_label": "Recorrência",
        "ai_diag": "**Diagnóstico:**",
        "ast_caption": "Hash da Árvore Sintática (AST): `{ast_hash}` | Última análise: `{timestamp}`",
        "orig_code": "❌ **Código Original Detectado (Read-Only):**",
        "fix_code": "✅ **Sugestão de Refatoração (Não Aplicada Automaticamente):**",
    },
}


def _build_markdown_export(df: pd.DataFrame) -> str:
    lines = ["# DataPulse AST Debugger Report\n"]
    for _, row in df.iterrows():
        lines.append(
            f"## [{row['severity']}] `{row['access_point_id']}` — `{row['error_category']}` "
            f"(Recurrence: {row['recurrence_count']}x)\n"
            f"- **File:** `{row['file_path']}`\n"
            f"- **Diagnostic:** {row['diagnostic_summary']}\n\n"
            f"```{row['language']}\n{row['original_code']}\n```\n"
        )
    return "\n".join(lines)


# Initialize local engines
memory = LocalDiagnosticMemory()
parser = MultiLangASTParser()

if "show_exit_modal" not in st.session_state:
    st.session_state.show_exit_modal = False

# --- SIDEBAR: LANGUAGE, SECURITY & SCANNING CONTROLS ---
with st.sidebar:
    ui_lang_choice = st.radio(
        "🌐 Language / Idioma:",
        options=["🇺🇸 English", "🇧🇷 Português"],
        horizontal=True,
    )
    lang_key = "en" if "English" in ui_lang_choice else "pt"
    t = I18N[lang_key]

    st.title("🛡️ DataPulse Debugger")
    st.caption(t["mode_caption"])
    st.divider()

    target_dir = st.text_input(t["target_dir"], value="./tests/sample_code")
    lang_filter = st.multiselect(
        t["monitored_langs"],
        options=["python", "sql", "r", "javascript"],
        default=["python", "sql", "r", "javascript"],
    )
    severity_filter = st.multiselect(
        t["severity_filter"],
        options=SEVERITY_ORDER,
        default=SEVERITY_ORDER,
    )
    allow_llm = st.checkbox(t["allow_llm"], value=False, help=t["allow_llm_help"])

    if st.button(t["scan_btn"], use_container_width=True, type="primary"):
        st.toast(t["scan_toast"], icon="🔒")
        agent = DataPulseAnalyzerAgent(memory=memory, parser=parser, allow_llm=allow_llm)
        scanned_records = agent.scan_directory(target_dir, languages=lang_filter)

        if not scanned_records:
            sample_record = DiagnosticRecord(
                file_path="src/etl/sales_pipeline.py",
                language="python",
                access_point_id="python:etl/sales_pipeline.py:process_chunk:L14-L39",
                ast_hash="8f9d2a7b3c4e5f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
                severity="HIGH",
                error_category="Pandas_Iterrows_Bottleneck",
                diagnostic_summary=(
                    "Explicit .iterrows() loop detected on large DataFrame. Causes severe CPU and memory degradation."
                    if lang_key == "en"
                    else "Loop explícito com .iterrows() detectado em DataFrame de grande volume. Causa degradação severa de CPU e memória."
                ),
                original_code="for idx, row in df.iterrows():\n    df.loc[idx, 'tax'] = row['price'] * 0.15",
                suggested_fix="df['tax'] = df['price'] * 0.15  # C-level vectorized operation",
            )
            memory.save_diagnostic(sample_record)
            st.success(t["scan_demo_saved"])
        else:
            st.success(t["scan_count_saved"].format(count=len(scanned_records)))

    st.divider()
    if st.button(t["exit_btn"], use_container_width=True):
        st.session_state.show_exit_modal = True

    with st.expander(t["clear_expander"]):
        confirm_clear = st.checkbox(t["clear_confirm"], key="confirm_clear_mem")
        if st.button(t["clear_btn"], disabled=not confirm_clear, use_container_width=True):
            removed = memory.clear_memory()
            st.info(t["clear_done"].format(count=removed))
            st.rerun()

# --- SESSION EXIT & OPT-IN GLOBAL CONTRIBUTION MODAL ---
if st.session_state.show_exit_modal:
    st.warning(t["modal_title"])
    st.markdown(t["modal_body"])

    diagnostics = memory.get_all_diagnostics()
    if diagnostics:
        all_ids = [d["access_point_id"] for d in diagnostics]
        preview_payload = memory.prepare_anonymized_global_payload(all_ids)

        with st.expander(t["inspect_json"]):
            st.json(preview_payload)

        col_yes, col_no = st.columns(2)
        with col_yes:
            if st.button(t["btn_authorize"], use_container_width=True, type="primary"):
                res = memory.submit_opt_in_telemetry(all_ids)
                if res.get("status") == "sent":
                    st.success(t["msg_sent"])
                else:
                    st.warning(t["msg_failed"])
                st.session_state.show_exit_modal = False
        with col_no:
            if st.button(t["btn_offline"], use_container_width=True):
                st.info(t["msg_offline"])
                st.session_state.show_exit_modal = False
    st.divider()

# --- MAIN DASHBOARD BODY ---
st.header(t["header"])

records = memory.get_all_diagnostics()

if not records:
    st.info(t["empty_info"])
else:
    df = pd.DataFrame(records)
    df = df[df["language"].isin(lang_filter) & df["severity"].isin(severity_filter)]

    # Top KPIs
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric(t["kpi_mapped"], len(df))
    kpi2.metric(t["kpi_critical"], len(df[df["severity"].isin(["CRITICAL", "HIGH"])]))
    kpi3.metric(t["kpi_recurrence"], int(max(0, df["recurrence_count"].sum() - len(df))))
    kpi4.metric(t["kpi_status"], t["kpi_status_val"])

    if df.empty:
        st.info(t["empty_filter"])
    else:
        exp1, exp2, _ = st.columns([1, 1, 4])
        with exp1:
            st.download_button(
                t["export_md"],
                data=_build_markdown_export(df),
                file_name="datapulse_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with exp2:
            st.download_button(
                t["export_json"],
                data=json.dumps(df.to_dict(orient="records"), indent=2, ensure_ascii=False),
                file_name="datapulse_report.json",
                mime="application/json",
                use_container_width=True,
            )

        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            fig_heat = px.bar(
                df,
                x="file_path",
                y="recurrence_count",
                color="severity",
                title=t["chart_heatmap"],
                category_orders={"severity": SEVERITY_ORDER},
                color_discrete_map=SEVERITY_COLORS,
            )
            st.plotly_chart(fig_heat, use_container_width=True)

        with col_chart2:
            fig_lang = px.pie(
                df,
                names="language",
                title=t["chart_pie"],
                hole=0.4,
            )
            st.plotly_chart(fig_lang, use_container_width=True)

        # Detailed Side-by-Side Inspector
        st.subheader(t["inspector_title"])
        df_sorted = df.assign(
            _rank=df["severity"].map({s: i for i, s in enumerate(SEVERITY_ORDER)})
        ).sort_values(["_rank", "recurrence_count"], ascending=[True, False])

        for _, row in df_sorted.iterrows():
            rec_badge = f"🔁 {t['recurrence_label']}: {row['recurrence_count']}x"
            with st.expander(
                f"[{row['severity']}] {row['access_point_id']} — {row['error_category']} ({rec_badge})"
            ):
                st.markdown(f"{t['ai_diag']} {row['diagnostic_summary']}")
                st.caption(
                    t["ast_caption"].format(
                        ast_hash=row["ast_hash"], timestamp=row["timestamp"]
                    )
                )

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(t["orig_code"])
                    st.code(row["original_code"], language=row["language"])
                with c2:
                    st.markdown(t["fix_code"])
                    st.code(row["suggested_fix"], language=row["language"])
