# File: sqlite_ai_assurance/app.py
import uuid
import pandas as pd
import streamlit as st
from vault_engine import SQLiteAssuredVault
from llm_router import AssuredHybridRouter
from trust_evaluator import run_trust_benchmark, run_llm_coherence_suite
from local_model_scanner import discover_local_models

st.set_page_config(page_title="SQLite Assured AI Vault & Local Model Harness", layout="wide")

@st.cache_resource
def get_vault():
    v = SQLiteAssuredVault("assured_vault.db")
    v.seed_domain_baselines("ALL")
    return v

@st.cache_resource
def get_router():
    return AssuredHybridRouter()

vault = get_vault()
router = get_router()

# Scan Laptop for Local Models
scan_data = discover_local_models()
local_models = scan_data["models"]
endpoints_status = scan_data["endpoints_status"]

st.title("🛡️ SQLite Assured AI Vault & Local LLM Coherence Harness")
st.caption(
    "Tracks: Track 3 (Privacy & Security) + Track 4 (Sustainability) + Track 5 (Governance & Bias Mitigation) | "
    "Zero-Leak Database Tokenisation, Local Inference & Socio-Technical Assurance"
)

# Sidebar: Discovered Laptop Models & Runtime Controls
st.sidebar.header("🖥️ Discovered Laptop AI Models")

model_options = {f"{m['name']} [{m['provider']}]": m["id"] for m in local_models}
selected_model_label = st.sidebar.selectbox(
    "Active Inference Engine / Small Local LLM:",
    list(model_options.keys()),
    index=len(model_options) - 1 if "Built-in Small LLM Enclave Simulator" in list(model_options.keys())[-1] else 0,
    help="Select any local model found on this laptop or the built-in deterministic enclave simulator."
)
selected_model_id = model_options[selected_model_label]

col_s1, col_s2 = st.sidebar.columns(2)
with col_s1:
    if st.button("🔄 Rescan Laptop", use_container_width=True):
        st.cache_resource.clear()
        st.rerun()
with col_s2:
    if st.button("📦 Load Baselines", use_container_width=True, help="Injects Finance, HR, and DevOps protected baselines into SQLite."):
        vault.seed_domain_baselines("ALL")
        st.sidebar.success("Domain baselines injected!")

# Server Daemon Indicators
st.sidebar.markdown(
    f"<small>Ollama: {'🟢 LIVE' if endpoints_status['ollama_live'] else '⚪ Offline'} | "
    f"LM Studio: {'🟢 LIVE' if endpoints_status['lm_studio_live'] else '⚪ Offline'} | "
    f"Rust Enclave: {'🟢 LIVE' if endpoints_status['rust_enclave_live'] else '⚪ Offline'}</small>",
    unsafe_allow_html=True
)

st.sidebar.markdown("---")
st.sidebar.header("⚙️ Assurance Baseline Controls")
fuzzy_threshold = st.sidebar.slider(
    "Fuzzy Spelling Threshold (Damerau-Levenshtein)",
    min_value=0.65, max_value=0.95, value=0.78, step=0.01,
    help="Catches human typos and misspellings before prompt leaves SQLite."
)
entropy_threshold = st.sidebar.slider(
    "Credential Shannon Entropy Threshold (bits/char)",
    min_value=3.0, max_value=4.5, value=3.65, step=0.05,
    help="Flags unknown API keys, connection passwords, and high-entropy secrets."
)
user_role = st.sidebar.selectbox(
    "Active Database User Role (For `ai_restore`)",
    ["ADMIN", "ANALYST", "EXTERNAL_USER"],
    help="Enforces role-based clearance. Only ADMIN can detokenise CRITICAL_SECRET or full PII."
)

st.sidebar.markdown("---")
st.sidebar.subheader("➕ Add Custom Protected Baseline")
with st.sidebar.form("add_base_form"):
    new_type = st.selectbox("Entity Type", [
        "APPLICANT_NAME", "POSTAL_CODE", "PROTECTED_ATTR",
        "CLIENT_NAME", "PERSON_NAME", "PROJECT_CODE",
        "DEFENCE_CLEARANCE", "SECRET_KEY"
    ])
    new_val = st.text_input("Baseline Value (e.g., Airbus or E1 6AN)")
    new_sens = st.selectbox("Sensitivity Level", ["PII", "CONFIDENTIAL", "CRITICAL_SECRET"])
    if st.form_submit_button("Add to SQLite Baseline") and new_val:
        vault.add_baseline(new_type, new_val, new_sens)
        st.sidebar.success(f"Added `{new_val}` to SQLite!")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "🚀 Live Multi-Scenario Workflow Demo",
    "🧠 Local LLM Coherence & Round-Trip Suite",
    "📊 Trust Verification & Typo Benchmark",
    "🗄️ SQLite Internal Tables & Audit CSV Export"
])

# -------------------------------------------------------------
# TAB 1: Real-World Workflow Scenarios & Live Execution
# -------------------------------------------------------------
with tab1:
    st.subheader("1. Enterprise Human Workflow & Bias Mitigation Scenarios")
    st.markdown(
        "Select a realistic human workflow scenario below to see how the SQLite Native Engine "
        "protects privacy, prevents credential leakage, and eliminates demographic bias before data hits the model:"
    )

    scenarios = {
        "Scenario 1: Credit Control & Fair Lending (Bias Mitigation)": {
            "description": "Blinds demographic attributes (Applicant Name, Marital Status, Postal Code / Redlining marker) so the AI underwrites strictly on financial merit without illegal bias.",
            "prompt": "Loan Application Underwriting: Please review mortgage eligibility for applicant Priya Patel (single mother, age 32) residing at BS16 1QY. Stated annual gross income is £68,000, requesting £240,000 loan with clean repayment history."
        },
        "Scenario 2: DevOps & SRE Incident (Zero-Leak API Keys & DSNs)": {
            "description": "Prevents production disaster by tokenising live API keys, private database IPs, and JWT tokens from urgent support tickets.",
            "prompt": "URGENT SRE Stack Incident: PaymentGatewayService deadlock reported by engineer Callum Cokburn at Synoptx. Database host is 192.168.1.200 using service token sk-proj-89fH2kL9pQ3mN7vX1zR4. Need immediate mitigation steps."
        },
        "Scenario 3: Blind Recruitment & HR CV Screening (Anti-Discrimination)": {
            "description": "Enforces Track 5 compliance by masking candidate names, graduation cohorts, and prestigious university proxies so evaluation is 100% merit-based.",
            "prompt": "Blind HR Review: Evaluate Senior Distributed Systems Engineer resume for Alexnder Cockbrn who graduated OxfordUniversity in 2015 and previously worked at BristolBusinessPark. Key competencies: Rust, SQLite, and Kafka."
        },
        "Scenario 4: Autonomous Agentic Tool-Calling Gateway": {
            "description": "Acts as an inline privacy interceptor for autonomous AI agents, stopping live credentials from leaving internal tools to remote LLM hosts.",
            "prompt": "Agent Tool Invocation: Telemetry sync for TridentNavl naval combat system under NATO-SECRT clearance. Execute remote container diagnostic using deploy key ghp_998877665544332211aabbccddeeff on cluster node 10.240.12.88."
        },
        "Scenario 5: Custom Real-Time Prompt": {
            "description": "Type any custom prompt containing typos, names, or passwords to test the live SQLite engine.",
            "prompt": "Hi team, please grant Synoptx analyst Calum access to LookoutEdg project on 192.168.1.200."
        }
    }

    choice = st.selectbox("Select Human Workflow Scenario:", list(scenarios.keys()))
    st.info(f"💡 **Workflow Context:** {scenarios[choice]['description']}")

    raw_prompt = st.text_area("Input Prompt (Simulating Real Human Input & Typos):", value=scenarios[choice]["prompt"], height=100)

    # Redaction Engine Selection: Non-LLM Math Algorithms vs Local Small LLM vs Hybrid
    st.markdown("##### 🎛️ Redaction Engine Mode")
    redaction_mode = st.radio(
        "Choose Redaction Mechanism:",
        [
            "⚙️ SQLite 3-Tier Algorithmic Engine (Fuzzy Damerau-Levenshtein + Soundex + Shannon Entropy)",
            "🧠 Local Small LLM (SLM) Directed Redaction (Zero-Egress Prompted Semantic Masking)",
            "🛡️ Hybrid Combined (Algorithmic Defense-in-Depth + Local SLM Directed Policy)"
        ],
        index=0,
        help="Switch between purely non-LLM mathematical algorithms and offline local SLM-directed redaction."
    )

    if "Local Small LLM" in redaction_mode or "Hybrid" in redaction_mode:
        default_inst = "Redact all applicant names, demographic proxies (marital status, age), postal codes, API keys, credentials, and internal hostnames."
        if "Credit Control" in choice:
            default_inst = "Redact all applicant names, demographic proxies, age, marital status, and postal codes/redlining markers to prevent credit bias."
        elif "DevOps" in choice:
            default_inst = "Redact all API keys, service tokens, database connection strings, passwords, and private IPv4 addresses."
        elif "Blind HR" in choice:
            default_inst = "Redact candidate names, graduation cohorts, and prestigious university proxies to ensure merit-based hiring."
        elif "Agentic" in choice:
            default_inst = "Redact all defense clearance levels, deploy tokens, cluster IPs, and military project codes."

        redaction_instruction = st.text_input(
            "Local SLM Redaction Policy / Instruction:",
            value=default_inst,
            help="Direct the local small model on exactly what categories or attributes to redact into {{ENTITY_01}} placeholders."
        )
    else:
        redaction_instruction = ""

    if st.button("▶️ Execute Redaction & Run Selected Model", type="primary"):
        session_id = f"sess_{uuid.uuid4().hex[:8]}"

        # Execution based on selected redaction engine mode
        if redaction_mode.startswith("⚙️"):
            redacted_prompt = vault.redact_text(
                raw_prompt,
                session_id=session_id,
                fuzzy_threshold=fuzzy_threshold,
                entropy_threshold=entropy_threshold
            )
            engine_desc = f"SQLite Native Engine: SELECT ai_redact(prompt, '{session_id}', {fuzzy_threshold})"
        elif redaction_mode.startswith("🧠"):
            slm_res = router.directed_local_ai_redact(
                raw_prompt,
                redaction_instruction=redaction_instruction,
                selected_model_id=selected_model_id
            )
            redacted_prompt = vault.register_ai_redaction(
                session_id=session_id,
                original_text=raw_prompt,
                redacted_text=slm_res["redacted_text"],
                extracted_tokens=slm_res["extracted_tokens"],
                elapsed_ms=slm_res["elapsed_ms"]
            )
            engine_desc = f"Local SLM Directed Parsing ({slm_res['engine_used']}) [Policy: {redaction_instruction[:40]}...]"
        else: # Hybrid
            step1_prompt = vault.redact_text(
                raw_prompt,
                session_id=session_id,
                fuzzy_threshold=fuzzy_threshold,
                entropy_threshold=entropy_threshold
            )
            slm_res = router.directed_local_ai_redact(
                step1_prompt,
                redaction_instruction=redaction_instruction,
                selected_model_id=selected_model_id
            )
            redacted_prompt = vault.register_ai_redaction(
                session_id=session_id,
                original_text=raw_prompt,
                redacted_text=slm_res["redacted_text"],
                extracted_tokens=slm_res["extracted_tokens"],
                elapsed_ms=slm_res["elapsed_ms"]
            )
            engine_desc = f"Hybrid Defense-in-Depth (SQLite 3-Tier Algorithmic + {slm_res['engine_used']})"

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

        if grey_rows:
            st.warning("⚠️ **Human-in-the-Loop Socio-Technical Alert:** Borderline typo matches detected!")
            st.dataframe(pd.DataFrame([dict(r) for r in grey_rows]), use_container_width=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"#### 🔒 Step 1: Redaction Engine ({'SLM Directed' if '🧠' in redaction_mode else ('Hybrid' if '🛡️' in redaction_mode else 'SQLite UDF')})")
            st.code(engine_desc, language="text")
            st.info(f"**Sanitized Prompt Sent to Model (Zero Raw PII/Secrets):**\n\n`{redacted_prompt}`")
            st.caption(
                f"Processing Overhead: **{audit_row['processing_ms']} ms** | "
                f"Tokens Redacted: **{len(vault_rows)}** | "
                f"Max Sensitivity: **{audit_row['max_sensitivity']}** | "
                f"Route Policy: **{audit_row['recommended_route']}**"
            )

        with col2:
            st.markdown("#### 🧠 Step 2: Model Inference & Detokenisation (`SELECT ai_restore(...)`)")
            llm_res = router.generate_response(
                redacted_prompt,
                route=audit_row["recommended_route"],
                selected_model_id=selected_model_id
            )
            st.code(f"-- Raw Model Reply (Placeholders Intact):\n{llm_res['reply']}", language="text")

            restored_reply = vault.execute_sql_restore(llm_res["reply"], session_id, user_role)
            st.success(f"**Detokenised Output for Role `{user_role}`:**\n\n{restored_reply}")
            coh = llm_res["coherence"]
            st.caption(
                f"Engine: **{llm_res['engine_used']}** | Latency: **{llm_res['latency_ms']} ms** | "
                f"Placeholder Survival: **{coh['placeholder_survival_pct']}%** | "
                f"Coherence Score: **{coh['coherence_score_pct']}%**"
            )

        if vault_rows:
            st.markdown("#### 🔍 Step 3: Live Session Token Vault & Regulatory Export")
            df_vault = pd.DataFrame([dict(r) for r in vault_rows])
            st.dataframe(df_vault, use_container_width=True)
            st.download_button(
                "📥 Export Session Audit Log (CSV)",
                data=df_vault.to_csv(index=False).encode("utf-8"),
                file_name=f"session_{session_id}_audit.csv",
                mime="text/csv",
                help="Instant regulatory compliance export (EU AI Act & SOC2 justification)."
            )

# -------------------------------------------------------------
# TAB 2: Local Laptop Model Coherence & Round-Trip Test Suite
# -------------------------------------------------------------
with tab2:
    st.subheader("🧠 Local Laptop AI Models & End-to-End Coherence Benchmark")
    st.markdown(
        "**Track 3 (Privacy) & Track 4 (Hardware Sustainability) Proof:** *'Protect user data without wrecking AI performance.'* "
        "Below are all AI models and weights discovered on this laptop. Run the automated suite to verify that smaller local models "
        "preserve semantic placeholders without mangling syntax and allow 100% lossless SQLite detokenisation."
    )

    df_models = pd.DataFrame(local_models)
    st.dataframe(df_models[["name", "provider", "size_gb", "param_size", "quantization", "status"]], use_container_width=True)

    st.markdown("---")
    st.markdown(f"#### Run Multi-Scenario Round-Trip Suite on: `{selected_model_label}`")

    if st.button(f"🚀 Execute 5-Scenario Coherence Benchmark", type="primary"):
        with st.spinner("Executing: SQLite Redact ➔ Local Model Inference ➔ Coherence Scoring ➔ SQLite Detokenise..."):
            suite_res = run_llm_coherence_suite(
                vault, router, selected_model_id=selected_model_id, fuzzy_threshold=fuzzy_threshold
            )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Placeholder Survival Rate", f"{suite_res['avg_placeholder_survival_pct']}%", help="% of {{ENTITY_01}} tokens preserved intact")
        c2.metric("Small-LLM Coherence Score", f"{suite_res['avg_coherence_score_pct']}%", help="Syntactic structure and response validity")
        c3.metric("Round-Trip SQLite Restore", f"{suite_res['avg_roundtrip_restore_pct']}%", help="% of placeholders cleanly detokenised back to ground truth")
        c4.metric("Avg Hardware Latency", f"{suite_res['avg_latency_ms']} ms", help="Local inference speed")

        df_suite = pd.DataFrame(suite_res["rows"])
        st.dataframe(df_suite, use_container_width=True)
        st.download_button(
            "📥 Export Coherence Benchmark Report (CSV)",
            data=df_suite.to_csv(index=False).encode("utf-8"),
            file_name="local_llm_coherence_benchmark.csv",
            mime="text/csv",
            help="Quantitative proof for hackathon judges."
        )

# -------------------------------------------------------------
# TAB 3: Trust Verification & Adversarial Typo Benchmark
# -------------------------------------------------------------
with tab3:
    st.subheader("Proving & Justifying Trust: Standard Regex vs. SQLite 3-Tier Baseline")
    st.markdown(
        "Standard DLP/Regex filters fail when humans make typos (`Cokburn`, `Synoptx`, `LookoutEdg`) "
        "or when unknown API keys are generated. This automated benchmark proves our 3-tier SQLite engine closes the responsibility gap."
    )

    if st.button("🧪 Run Adversarial Typo & Secret Benchmark Suite"):
        results = run_trust_benchmark(vault, fuzzy_threshold=fuzzy_threshold)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Standard Regex Recall", f"{results['naive_recall_pct']}%", delta=f"-{results['naive_leak_rate_pct']}% leaked", delta_color="inverse")
        m2.metric("SQLite Assured Vault Recall", f"{results['vault_recall_pct']}%", delta=f"+{round(results['vault_recall_pct'] - results['naive_recall_pct'], 1)}% improvement")
        m3.metric("Credential / Typo Leak Rate", f"{results['vault_leak_rate_pct']}%")
        m4.metric("Total Suite Latency", f"{results['benchmark_latency_ms']} ms")
        st.dataframe(pd.DataFrame(results["details"]), use_container_width=True)

# -------------------------------------------------------------
# TAB 4: SQLite Internal Tables & Audit CSV Export
# -------------------------------------------------------------
with tab4:
    st.subheader("SQLite Native Tables (`sensitive_baseline` & `assurance_audit_log`)")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Protected Baseline Table (`sensitive_baseline`)**")
        b_rows = vault.conn.execute("SELECT * FROM sensitive_baseline ORDER BY id DESC").fetchall()
        st.dataframe(pd.DataFrame([dict(r) for r in b_rows]), use_container_width=True)
    with c2:
        st.markdown("**Immutable Governance Audit Log (`assurance_audit_log`)**")
        a_rows = vault.conn.execute("SELECT * FROM assurance_audit_log ORDER BY id DESC LIMIT 50").fetchall()
        df_audit = pd.DataFrame([dict(r) for r in a_rows])
        st.dataframe(df_audit, use_container_width=True)
        if not df_audit.empty:
            st.download_button(
                "📥 Export Full Governance Audit Log (CSV)",
                data=df_audit.to_csv(index=False).encode("utf-8"),
                file_name="assurance_audit_log_full.csv",
                mime="text/csv",
                help="Instant export of all governance audit entries for compliance regulators."
            )
