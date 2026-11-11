import sys
from pathlib import Path

# Garante que a raiz do projeto esteja no sys.path ao executar `streamlit run dashboard/app.py`
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

# Inicialização dos motores locais
memory = LocalDiagnosticMemory()
parser = MultiLangASTParser()
agent = DataPulseAnalyzerAgent(memory=memory, parser=parser)

if "show_exit_modal" not in st.session_state:
    st.session_state.show_exit_modal = False

# --- SIDEBAR: CONTROLE DE SEGURANÇA E ESCANEAMENTO ---
with st.sidebar:
    st.title("🛡️ DataPulse Debugger")
    st.caption("Modo: **100% Read-Only & Local Memory**")
    st.divider()

    target_dir = st.text_input("Diretório do Projeto Alvo:", value="./tests/sample_code")
    lang_filter = st.multiselect(
        "Linguagens Monitoradas:",
        options=["python", "sql", "r"],
        default=["python", "sql", "r"],
    )

    if st.button("🔍 Mapear AST & Diagnosticar", use_container_width=True, type="primary"):
        st.toast("Escaneando AST em modo Read-Only...", icon="🔒")
        scanned_records = agent.scan_directory(target_dir, languages=lang_filter)

        if not scanned_records:
            # Caso o diretório esteja vazio, insere registro de demonstração
            sample_record = DiagnosticRecord(
                file_path="src/etl/sales_pipeline.py",
                language="python",
                access_point_id="python:sales_pipeline.py:process_chunk:L14-L39",
                ast_hash="8f9d2a7b3c4e5f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
                severity="HIGH",
                error_category="Pandas_Iterrows_Bottleneck",
                diagnostic_summary="Loop explícito com .iterrows() detectado em DataFrame de grande volume. Causa degradação severa de CPU e memória.",
                original_code="for idx, row in df.iterrows():\n    df.loc[idx, 'tax'] = row['price'] * 0.15",
                suggested_fix="df['tax'] = df['price'] * 0.15  # Operação vetorizada C-level",
            )
            memory.save_diagnostic(sample_record)
            st.success("Diagnóstico salvo na memória local (.datapulse_memory)!")
        else:
            st.success(
                f"{len(scanned_records)} ponto(s) de acesso diagnosticado(s) e salvo(s) em .datapulse_memory!"
            )

    st.divider()
    if st.button("🚪 Encerrar Sessão / Fechar Relatório", use_container_width=True):
        st.session_state.show_exit_modal = True

# --- MODAL DE ENCERRAMENTO E CONTRIBUIÇÃO GLOBAL OPT-IN ---
if st.session_state.show_exit_modal:
    st.warning("### 🤝 Contribuição Opcional para o Banco Global de Soluções")
    st.markdown(
        """
        Sua sessão de diagnóstico está sendo encerrada. Todos os dados permanecem **exclusivamente na sua máquina**.
        Deseja ajudar a comunidade enviando **apenas os metadados anonimizados** (hashes de AST e categorias de erro) dos problemas descobertos hoje?
        
        *🔒 **Garantia de Privacidade:** Seu código-fonte, nomes de arquivos e variáveis **jamais** são transmitidos.*
        """
    )

    diagnostics = memory.get_all_diagnostics()
    if diagnostics:
        all_ids = [d["access_point_id"] for d in diagnostics]
        preview_payload = memory.prepare_anonymized_global_payload(all_ids)

        with st.expander("👁️ Inspecionar exatamente o JSON que será enviado (Auditoria Transparente)"):
            st.json(preview_payload)

        col_yes, col_no = st.columns(2)
        with col_yes:
            if st.button(
                "✅ Autorizar e Enviar Metadados Anonimizados",
                use_container_width=True,
                type="primary",
            ):
                memory.submit_opt_in_telemetry(all_ids)
                st.success(
                    "Obrigado! Assinaturas de erro compartilhadas com sucesso. Você já pode fechar a aba."
                )
                st.session_state.show_exit_modal = False
        with col_no:
            if st.button("❌ Não Enviar (Manter 100% Offline)", use_container_width=True):
                st.info("Sessão encerrada sem envio externo. Memória local preservada.")
                st.session_state.show_exit_modal = False
    st.divider()

# --- CORPO PRINCIPAL DO DASHBOARD ---
st.header("📊 Relatório de Diagnóstico & Pontos de Acesso AST")

records = memory.get_all_diagnostics()

if not records:
    st.info(
        "Nenhum diagnóstico na memória local ainda. Clique em **Mapear AST & Diagnosticar** na barra lateral."
    )
else:
    df = pd.DataFrame(records)
    df = df[df["language"].isin(lang_filter)]

    # KPIs Superiores
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Pontos de Acesso Mapeados", len(df))
    kpi2.metric("Alertas Críticos / Altos", len(df[df["severity"].isin(["CRITICAL", "HIGH"])]))
    kpi3.metric("Reincidências na Memória", int(df["recurrence_count"].sum() - len(df)))
    kpi4.metric("Status do Repositório", "Read-Only Seguro 🔒")

    if not df.empty:
        # Gráficos de Telemetria (Heatmap de Arquivos e Distribuição por Linguagem)
        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            fig_heat = px.bar(
                df,
                x="file_path",
                y="recurrence_count",
                color="severity",
                title="Heatmap de Incidência e Recorrência por Arquivo",
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#3b82f6",
                },
            )
            st.plotly_chart(fig_heat, use_container_width=True)

        with col_chart2:
            fig_lang = px.pie(
                df,
                names="language",
                title="Distribuição de Diagnósticos por Linguagem (Python, SQL, R)",
                hole=0.4,
            )
            st.plotly_chart(fig_lang, use_container_width=True)

        # Inspetor Detalhado Lado a Lado
        st.subheader("🔬 Inspetor de Pontos de Acesso (Lado a Lado)")
        for _, row in df.iterrows():
            with st.expander(
                f"[{row['severity']}] {row['access_point_id']} — {row['error_category']} (Recorrência: {row['recurrence_count']}x)"
            ):
                st.markdown(f"**Diagnóstico da IA:** {row['diagnostic_summary']}")
                st.caption(
                    f"Hash da Árvore Sintática (AST): `{row['ast_hash']}` | Última análise: `{row['timestamp']}`"
                )

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("❌ **Código Original Detectado (Read-Only):**")
                    st.code(row["original_code"], language=row["language"])
                with c2:
                    st.markdown("✅ **Sugestão de Refatoração (Não Aplicada Automaticamente):**")
                    st.code(row["suggested_fix"], language=row["language"])
