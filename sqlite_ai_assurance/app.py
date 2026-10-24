# File: app.py
import uuid
import pandas as pd
import streamlit as st
from vault_engine import SQLiteAssuredVault
from llm_router import AssuredHybridRouter
from trust_evaluator import run_trust_benchmark

st.set_page_config(page_title="SQLite Assured AI Vault", layout="wide")

@st.cache_resource
def get_vault():
    return SQLiteAssuredVault("assured_vault.db")

@st.cache_resource
def get_router():
    return AssuredHybridRouter()

vault = get_vault()
router = get_router()

st.title("🛡️ SQLite Assured AI Vault & Hybrid Rust Router")
st.caption(
    "Tracks: Track 3 (Privacy & Security) + Track 4 (Sustainability) + Track 5 (Governance & Compliance) | "
    "Closing the Responsibility Gap at the Database & Inference Layer"
)

# Sidebar Controls: Human-in-the-Loop & Baseline Tuning
st.sidebar.header("⚙️ Assurance Baseline Controls")
fuzzy_threshold = st.sidebar.slider(
    "Fuzzy Spelling Threshold (Damerau-Levenshtein)",
    min_value=0.65, max_value=0.95, value=0.78, step=0.01,
    help="Catches human typos (e.g., 'Synoptx' -> 'Synoptix') before data leaves SQLite."
)
entropy_threshold = st.sidebar.slider(
    "Credential Shannon Entropy Threshold ( bits/char )",
    min_value=3.0, max_value=4.5, value=3.65, step=0.05,
    help="Automatically detects unknown API keys, passwords, and high-entropy secrets."
)
user_role = st.sidebar.selectbox(
    "Active Database User Role (For `ai_restore`)",
    ["ADMIN", "ANALYST", "EXTERNAL_USER"],
    help="Controls which sensitivity tiers get detokenised when the AI response comes back."
)

st.sidebar.markdown("---")
st.sidebar.subheader("➕ Add Custom Protected Baseline")
with st.sidebar.form("add_base_form"):
    new_type = st.selectbox("Entity Type", ["CLIENT_NAME", "PERSON_NAME", "PROJECT_CODE", "DEFENCE_CLEARANCE"])
    new_val = st.text_input("Baseline Value (e.g., Airbus)")
    new_sens = st.selectbox("Sensitivity Level", ["PII", "CONFIDENTIAL", "CRITICAL_SECRET"])
    if st.form_submit_button("Add to SQLite Baseline") and new_val:
        vault.add_baseline(new_type, new_val, new_sens)
        st.sidebar.success(f"Added `{new_val}` (Soundex: `{new_val[:4]}`) to SQLite!")

tab1, tab2, tab3 = st.tabs([
    "🚀 Live SQLite Tokenisation & Hybrid Routing Demo",
    "📊 Trust Verification & Typo Benchmark (Judge Proof)",
    "🗄️ SQLite Internal Tables & Audit Trail"
])

with tab1:
    st.subheader("1. Input Prompt (Simulating Real Human Typos & Leaked Credentials)")
    sample_prompts = {
        "Scenario A: Human Typos + Leaked OpenAI Key": (
            "Hi team, engineer Callum Cokburn from Synoptx needs us to debug the customer portal "
            "using API key sk-proj-89fH2kL9pQ3mN7vX1zR4 and email callum.c@synoptix.co.uk."
        ),
        "Scenario B: Critical Defence Project (Triggers Local Rust Enclave)": (
            "URGENT: Upload telemetry for project LookoutEdg under NATO-SECRT clearance "
            "using access token ghp_998877665544332211aabbccddeeff for NetwrkRail."
        ),
        "Scenario C: Borderline Human Typo (Triggers Human-in-the-Loop Grey Zone)": (
            "Can someone check if Sinoptx or Alexndr submitted the safety report from BristlBusinessPark?"
        )
    }
    choice = st.selectbox("Select Demo Scenario or Type Your Own:", list(sample_prompts.keys()))
    raw_prompt = st.text_area("Raw User Input:", value=sample_prompts[choice], height=90)

    if st.button("▶️ Execute SQLite `SELECT ai_redact(...)` & Route to AI", type="primary"):
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        redacted_prompt = vault.redact_text(
            raw_prompt,
            session_id=session_id,
            fuzzy_threshold=fuzzy_threshold,
            entropy_threshold=entropy_threshold
        )

        cur = vault.conn.cursor()
        audit_row = cur.execute(
            "SELECT * FROM assurance_audit_log WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (session_id,)
        ).fetchone()
        vault_rows = cur.execute(
            "SELECT placeholder, raw_value, entity_type, match_method, similarity_score, sensitivity_level "
            "FROM token_vault WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        grey_rows = cur.execute(
            "SELECT user_word, matched_baseline, entity_type, similarity_score "
            "FROM grey_zone_alerts WHERE session_id = ?",
            (session_id,)
        ).fetchall()

        # Human-in-the-loop alert if borderline typos detected
        if grey_rows:
            st.warning(
                "⚠️ **Human-in-the-Loop Assurance Alert:** Borderline spelling match detected! "
                "Because the user is part of the socio-technical system, review these ambiguous tokens:"
            )
            st.dataframe(pd.DataFrame([dict(r) for r in grey_rows]), use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### 🔒 Step 1: Inside SQLite (`SELECT ai_redact(...)`)")
            st.code(
                f"SELECT ai_redact(prompt, '{session_id}', {fuzzy_threshold}) FROM prompts;",
                language="sql"
            )
            st.info(f"**What leaves the database (Zero Raw Secrets):**\n\n`{redacted_prompt}`")
            st.caption(
                f"SQLite Processing Overhead: **{audit_row['processing_ms']} ms** | "
                f"Max Sensitivity: **{audit_row['max_sensitivity']}** | "
                f"Selected Route: **{audit_row['recommended_route']}**"
            )

        with col2:
            st.markdown("#### 🧠 Step 2: AI Inference & Role-Based Restoration (`SELECT ai_restore(...)`)")
            llm_res = router.generate_response(redacted_prompt, route=audit_row["recommended_route"])
            st.code(f"-- Raw AI Reply (Before Detokenisation):\n{llm_res['reply']}", language="text")

            restored_reply = vault.execute_sql_restore(llm_res["reply"], session_id, user_role)
            st.success(f"**Restored Output for Role `{user_role}`:**\n\n{restored_reply}")
            st.caption(
                f"Inference Engine: **{llm_res['engine_used']}** | "
                f"Latency: **{llm_res['latency_ms']} ms** | "
                f"RAM Zeroized: **{llm_res['ram_zeroized']}**"
            )

        st.markdown("#### 🔍 Step 3: Live Token Vault Mapping for This Session")
        if vault_rows:
            st.dataframe(pd.DataFrame([dict(r) for r in vault_rows]), use_container_width=True)

        # One-Click Governance Audit Log CSV Export for this session
        session_audit_df = pd.DataFrame([dict(audit_row)]) if audit_row else pd.DataFrame()
        if not session_audit_df.empty:
            st.download_button(
                label="📥 Export Session Governance Audit Log (CSV)",
                data=session_audit_df.to_csv(index=False).encode('utf-8'),
                file_name=f"audit_log_{session_id}.csv",
                mime="text/csv",
                help="Instant export of this session's assurance verification and routing audit for regulatory compliance."
            )

with tab2:
    st.subheader("Proving & Justifying Trust: Standard Regex vs. SQLite Fuzzy+Entropy Baseline")
    st.markdown(
        "Standard DLP/Regex filters fail when humans make typos (`Cokburn`, `Synoptx`, `LookoutEdg`). "
        "Run the automated benchmark below to evaluate how our 3-tier SQLite engine closes the responsibility gap."
    )
    if st.button("🧪 Run Live Assurance Benchmark Suite"):
        results = run_trust_benchmark(vault, fuzzy_threshold=fuzzy_threshold)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Standard Regex Recall", f"{results['naive_recall_pct']}%", delta=f"-{results['naive_leak_rate_pct']}% leaked", delta_color="inverse")
        m2.metric("SQLite Assured Vault Recall", f"{results['vault_recall_pct']}%", delta=f"+{round(results['vault_recall_pct'] - results['naive_recall_pct'], 1)}% improvement")
        m3.metric("Credential / Typo Leak Rate", f"{results['vault_leak_rate_pct']}%")
        m4.metric("Total Suite Execution Time", f"{results['benchmark_latency_ms']} ms")

        st.dataframe(pd.DataFrame(results["details"]), use_container_width=True)

with tab3:
    st.subheader("SQLite Native Tables (`sensitive_baseline` & `assurance_audit_log`)")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Protected Baseline Table (`sensitive_baseline`)**")
        b_rows = vault.conn.execute("SELECT * FROM sensitive_baseline").fetchall()
        st.dataframe(pd.DataFrame([dict(r) for r in b_rows]), use_container_width=True)
    with c2:
        st.markdown("**Immutable Governance Audit Log (`assurance_audit_log`)**")
        a_rows = vault.conn.execute("SELECT * FROM assurance_audit_log ORDER BY id DESC LIMIT 50").fetchall()
        audit_df = pd.DataFrame([dict(r) for r in a_rows])
        st.dataframe(audit_df, use_container_width=True)
        if not audit_df.empty:
            st.download_button(
                label="📥 Export Governance Audit Log (CSV)",
                data=audit_df.to_csv(index=False).encode('utf-8'),
                file_name="assurance_audit_log_full.csv",
                mime="text/csv",
                help="Instant export of all governance audit entries for compliance reports (GDPR, EU AI Act, SOC2)."
            )
