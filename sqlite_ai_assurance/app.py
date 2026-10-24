# File: sqlite_ai_assurance/app.py — ChatGPT-Style Assured Chat with Real SQLite Backend
import re, uuid, time
import pandas as pd
import streamlit as st
from vault_engine import SQLiteAssuredVault
from llm_router import AssuredHybridRouter
from local_model_scanner import discover_local_models
from trust_evaluator import run_trust_benchmark, run_llm_coherence_suite

# ── Page Config ──────────────────────────────────────────────────────
st.set_page_config(page_title="Assured AI Vault", page_icon="🛡️", layout="wide")

# ═══════════════════════════════════════════════════════════════════════
# GLOBAL CSS — ChatGPT-style minimal white/black design
# ═══════════════════════════════════════════════════════════════════════
st.markdown("""<style>
/* ── Root & body ─────────────────────────────────────────── */
.stApp { background-color: #ffffff; }
header[data-testid="stHeader"] { background: #ffffff; border-bottom: 1px solid #e5e7eb; }

/* ── Sidebar ─────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background-color: #f9f9f9;
    border-right: 1px solid #e5e7eb;
    min-width: 260px; max-width: 280px;
    padding-top: 1rem;
}
[data-testid="stSidebar"] * { color: #1a1a1a !important; }
[data-testid="stSidebar"] .stMarkdown p,
[data-testid="stSidebar"] .stMarkdown h1,
[data-testid="stSidebar"] .stMarkdown h2,
[data-testid="stSidebar"] .stMarkdown h3,
[data-testid="stSidebar"] .stMarkdown h4 { color: #1a1a1a !important; }

/* Sidebar New Chat button — outlined, not filled */
[data-testid="stSidebar"] button[kind="primary"] {
    background-color: transparent !important;
    color: #1a1a1a !important;
    border: 1px solid #d1d5db !important;
    border-radius: 8px !important;
    font-weight: 500 !important;
    transition: background-color 0.15s ease;
}
[data-testid="stSidebar"] button[kind="primary"]:hover {
    background-color: #f0f0f0 !important;
}

/* Sidebar conversation buttons — ghost style */
[data-testid="stSidebar"] button[kind="secondary"],
[data-testid="stSidebar"] button:not([kind]) {
    background-color: transparent !important;
    border: none !important;
    border-radius: 8px !important;
    color: #374151 !important;
    font-size: 0.88rem !important;
    text-align: left !important;
    padding: 6px 10px !important;
    transition: background-color 0.15s ease;
}
[data-testid="stSidebar"] button[kind="secondary"]:hover,
[data-testid="stSidebar"] button:not([kind]):hover {
    background-color: #ececec !important;
}

/* Sidebar select boxes */
[data-testid="stSidebar"] .stSelectbox > div > div {
    background-color: #ffffff !important;
    border: 1px solid #d1d5db !important;
    border-radius: 8px !important;
}

/* Sidebar radio */
[data-testid="stSidebar"] .stRadio label span { font-size: 0.88rem !important; }

/* Sidebar dividers */
[data-testid="stSidebar"] hr { border-color: #e5e7eb !important; margin: 8px 0 !important; }

/* ── Tabs — minimal underline style ──────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    border-bottom: 1px solid #e5e7eb;
    background: transparent;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    color: #6b7280 !important;
    font-size: 0.9rem !important;
    font-weight: 500 !important;
    padding: 10px 20px !important;
    border-bottom: 2px solid transparent !important;
    transition: all 0.15s ease;
}
.stTabs [data-baseweb="tab"]:hover { color: #111827 !important; }
.stTabs [data-baseweb="tab"][aria-selected="true"] {
    color: #111827 !important;
    border-bottom: 2px solid #111827 !important;
    font-weight: 600 !important;
}

/* ── Chat messages ───────────────────────────────────────── */
div.stChatMessage { max-width: 760px; margin: auto; }
[data-testid="stChatMessage"] {
    background-color: #ffffff !important;
    border: none !important;
    padding: 16px 0 !important;
}

/* ── Chat input — pill shaped like ChatGPT ───────────────── */
[data-testid="stChatInput"] > div {
    max-width: 760px;
    margin: 0 auto;
}
[data-testid="stChatInput"] textarea {
    border-radius: 24px !important;
    border: 1px solid #d1d5db !important;
    padding: 12px 20px !important;
    font-size: 0.95rem !important;
    background-color: #f9fafb !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04) !important;
}
[data-testid="stChatInput"] textarea:focus {
    border-color: #9ca3af !important;
    box-shadow: 0 1px 6px rgba(0,0,0,0.08) !important;
}
[data-testid="stChatInput"] button {
    background-color: #111827 !important;
    color: #ffffff !important;
    border-radius: 50% !important;
    width: 36px !important; height: 36px !important;
}

/* ── Redaction badge pills ───────────────────────────────── */
.pill { display:inline-block; padding:2px 8px; border-radius:12px; font-size:.82em; font-weight:600; margin:0 2px; }
.pill-pii    { background:#dbeafe; color:#1e40af; }
.pill-secret { background:#fee2e2; color:#991b1b; }
.pill-conf   { background:#fef3c7; color:#92400e; }
.pill-route  { background:#d1fae5; color:#065f46; }

/* ── Sanitised block ─────────────────────────────────────── */
.san-block {
    background: #f8fafc; border-left: 3px solid #cbd5e1;
    padding: 10px 14px; border-radius: 6px; margin-top: 8px;
    font-size: 0.9rem; color: #334155;
}
.san-block small { color: #64748b; font-weight: 700; }

/* ── Metric cards ────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #f9fafb; border: 1px solid #e5e7eb;
    border-radius: 10px; padding: 14px !important;
}
[data-testid="stMetric"] label { color: #6b7280 !important; font-size: 0.82rem !important; }
[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #111827 !important; font-weight: 700 !important; }

/* ── Dataframes ──────────────────────────────────────────── */
.stDataFrame { border-radius: 8px; overflow: hidden; border: 1px solid #e5e7eb; }

/* ── Expanders ───────────────────────────────────────────── */
details[data-testid="stExpander"] {
    border: 1px solid #e5e7eb !important;
    border-radius: 8px !important;
    background: #fafafa !important;
}
details[data-testid="stExpander"] summary span { font-size: 0.88rem !important; color: #374151 !important; }

/* ── Buttons (general) ───────────────────────────────────── */
.stButton > button {
    background-color: #ffffff !important;
    border: 1px solid #d1d5db !important;
    border-radius: 8px !important;
    color: #374151 !important;
    font-weight: 500 !important;
    font-size: 0.88rem !important;
    transition: all 0.15s ease;
}
.stButton > button:hover {
    background-color: #f3f4f6 !important;
    border-color: #9ca3af !important;
}

/* ── Download button ─────────────────────────────────────── */
.stDownloadButton > button {
    background-color: #111827 !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 8px !important;
}
.stDownloadButton > button:hover { background-color: #374151 !important; }

/* ── Scenario cards (empty state) ────────────────────────── */
.scenario-card {
    border: 1px solid #e5e7eb; border-radius: 12px;
    padding: 16px; cursor: pointer;
    transition: all 0.2s ease; background: #ffffff;
}
.scenario-card:hover { border-color: #9ca3af; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
.scenario-label { font-weight: 600; font-size: 0.95rem; color: #111827; margin-bottom: 4px; }
.scenario-desc { font-size: 0.82rem; color: #6b7280; line-height: 1.35; }

/* ── Hero text ───────────────────────────────────────────── */
.hero-title {
    text-align: center; font-size: 1.6rem; font-weight: 300;
    color: #1a1a1a; margin-top: 18vh;
}
.hero-sub {
    text-align: center; font-size: 0.92rem; color: #9ca3af;
    margin-bottom: 32px;
}

/* ── Hide Streamlit branding ─────────────────────────────── */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
</style>""", unsafe_allow_html=True)

# ── Singletons ───────────────────────────────────────────────────────
@st.cache_resource
def boot():
    v = SQLiteAssuredVault("assured_vault.db")
    v.seed_domain_baselines("ALL")
    r = AssuredHybridRouter()
    v.seed_default_conversations_if_empty(r)
    return v, r

vault, router = boot()
scan = discover_local_models()
models = scan["models"]
ep = scan["endpoints_status"]

# ── Helper: colour-badge placeholders ────────────────────────────────
def badge(text):
    def _rep(m):
        p = m.group(0); inner = p.strip("{}")
        if any(k in inner for k in ("KEY","SECRET","TOKEN","PASS","CLEARANCE")):
            return f'<span class="pill pill-secret">{p}</span>'
        if any(k in inner for k in ("NAME","PERSON","APPLICANT","CANDIDATE","POSTAL","MARITAL","AGE","INSTITUTION","GRADUATION")):
            return f'<span class="pill pill-pii">{p}</span>'
        return f'<span class="pill pill-conf">{p}</span>'
    return re.sub(r'\{\{[A-Z0-9_]+\}\}', _rep, text)

# ═══════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("#### Assured AI Vault")

    if st.button("+ New chat", use_container_width=True, type="primary"):
        cid = vault.create_conversation("New chat")
        st.session_state["cid"] = cid
        st.rerun()

    st.markdown("---")
    st.caption("Recents")

    convos = vault.list_conversations()
    if "cid" not in st.session_state or not any(c["id"]==st.session_state["cid"] for c in convos):
        st.session_state["cid"] = convos[0]["id"] if convos else vault.create_conversation("New chat")

    for c in convos:
        active = c["id"] == st.session_state["cid"]
        cols = st.columns([.88, .12])
        with cols[0]:
            label = c["title"][:36]
            if st.button(label, key=f"n_{c['id']}", use_container_width=True):
                st.session_state["cid"] = c["id"]; st.rerun()
        with cols[1]:
            if st.button("x", key=f"d_{c['id']}"):
                vault.delete_conversation(c["id"]); st.rerun()

    st.markdown("---")

    # ── Controls ─────────────────────────────────────────────────────
    model_map = {f"{m['name'][:40]}": m["id"] for m in models}
    sel_model = st.selectbox("Model", list(model_map), index=len(model_map)-1)
    sel_model_id = model_map[sel_model]

    ol = "ON" if ep["ollama_live"] else "off"
    lm = "ON" if ep["lm_studio_live"] else "off"
    ru = "ON" if ep["rust_enclave_live"] else "off"
    st.caption(f"Ollama {ol}  |  LM Studio {lm}  |  Rust {ru}")

    redact_mode = st.radio("Redaction Engine", [
        "Algorithmic (Fuzzy+Soundex+Entropy)",
        "Local SLM Directed",
        "Hybrid (Algo + SLM)"
    ], index=0, label_visibility="visible")

    if "SLM" in redact_mode:
        slm_policy = st.text_input("SLM policy", value="Redact names, demographic proxies, postal codes, API keys, credentials.")
    else:
        slm_policy = ""

    role = st.selectbox("RBAC Role", ["ADMIN","ANALYST","EXTERNAL_USER"])

    with st.expander("Advanced thresholds"):
        fuzz_t = st.slider("Fuzzy DL", .65, .95, .78, .01)
        ent_t  = st.slider("Shannon H", 3.0, 4.5, 3.65, .05)

# ═══════════════════════════════════════════════════════════════════════
# MAIN AREA — Tabs
# ═══════════════════════════════════════════════════════════════════════
tab_chat, tab_bench, tab_audit, tab_docs = st.tabs([
    "Chat", "Benchmarks", "Audit & Tables", "How It Works"
])

# ─── helper: run the full redact -> infer -> restore pipeline ────────
def run_pipeline(raw_text: str):
    sid = f"s_{uuid.uuid4().hex[:8]}"

    # 1. Redaction
    if redact_mode.startswith("Algorithmic"):
        sanitized = vault.redact_text(raw_text, sid, fuzz_t, entropy_threshold=ent_t)
        eng = "SQLite 3-Tier Algorithmic"
    elif redact_mode.startswith("Local SLM"):
        res = router.directed_local_ai_redact(raw_text, slm_policy, sel_model_id)
        sanitized = vault.register_ai_redaction(sid, raw_text, res["redacted_text"], res["extracted_tokens"], res["elapsed_ms"])
        eng = f"Local SLM ({res['engine_used']})"
    else:
        step1 = vault.redact_text(raw_text, sid, fuzz_t, entropy_threshold=ent_t)
        res = router.directed_local_ai_redact(step1, slm_policy, sel_model_id)
        sanitized = vault.register_ai_redaction(sid, raw_text, res["redacted_text"], res["extracted_tokens"], res["elapsed_ms"])
        eng = "Hybrid (Algo + SLM)"

    # 2. Route
    cur = vault.conn.cursor()
    ar = cur.execute("SELECT recommended_route FROM assurance_audit_log WHERE session_id=? ORDER BY id DESC LIMIT 1",(sid,)).fetchone()
    route = ar["recommended_route"] if ar else "CLOUD_API_SAFE"

    # 3. Inference
    llm = router.generate_response(sanitized, route=route, selected_model_id=sel_model_id)
    reply   = llm["reply"]
    lat     = llm["latency_ms"]
    tps     = llm.get("tokens_per_sec", 0)

    # 4. Restore
    restored = vault.execute_sql_restore(reply, sid, role)

    return sid, sanitized, reply, restored, eng, route, lat, tps

# ═══════════════════════════════════════════════════════════════════════
# TAB 1 — CHAT
# ═══════════════════════════════════════════════════════════════════════
with tab_chat:
    cid = st.session_state["cid"]
    msgs = vault.get_conversation_messages(cid)

    # ── Empty state hero ─────────────────────────────────────────────
    if not msgs:
        st.markdown('<p class="hero-title">Good to see you, Shivam.</p>', unsafe_allow_html=True)
        st.markdown('<p class="hero-sub">Ask anything — test typos, paste secrets, or try a scenario below.</p>', unsafe_allow_html=True)

        SCENARIOS = [
            ("Credit Control",  "Review mortgage for Priya Patel (single mother, age 32) at BS16 1QY. Income 68,000, requesting 240,000 loan."),
            ("DevOps SRE",      "URGENT: Deadlock on PaymentGateway reported by Callum Cokburn at Synoptx. DB host 192.168.1.200, token sk-proj-89fH2kL9pQ3mN7vX1zR4."),
            ("Blind HR",        "Evaluate resume for Alexnder Cockbrn, graduated OxfordUniversity 2015, worked at BristolBusinessPark. Skills: Rust, SQLite, Kafka."),
            ("Agentic Gateway", "Telemetry sync TridentNavl under NATO-SECRT. Deploy key ghp_998877665544332211aabbccddeeff on node 10.240.12.88."),
        ]
        cols = st.columns(2, gap="medium")
        for i, (label, prompt) in enumerate(SCENARIOS):
            with cols[i % 2]:
                if st.button(label, key=f"sc_{i}", use_container_width=True):
                    vault.conn.execute("UPDATE chat_conversations SET title=?,scenario_type=? WHERE id=?",(label,"SCENARIO",cid))
                    vault.conn.commit()
                    sid, san, rep, rest, eng, route, lat, tps = run_pipeline(prompt)
                    vault.add_chat_turn(cid, sid, prompt, san, rep, rest, eng, route, lat, tps)
                    st.rerun()

    # ── Render persisted messages from SQLite ─────────────────────────
    for m in msgs:
        sid = m["session_id"]

        # USER turn
        with st.chat_message("user"):
            st.markdown(m["user_raw"])
            st.markdown(
                f'<div class="san-block">'
                f'<small>Sanitised (sent to model):</small><br>'
                f'{badge(m["sanitized_content"])}</div>',
                unsafe_allow_html=True
            )
            # Live SQLite token vault query
            rows = vault.conn.execute(
                "SELECT placeholder,raw_value,entity_type,match_method,similarity_score,sensitivity_level FROM token_vault WHERE session_id=?",(sid,)
            ).fetchall()
            with st.expander(f"Token vault  ({len(rows)} tokens)"):
                if rows: st.dataframe(pd.DataFrame([dict(r) for r in rows]), use_container_width=True)
                st.caption(f"Engine: **{m['redaction_engine']}** | Route: **{m['route_policy']}** | {m['latency_ms']} ms")

        # ASSISTANT turn
        with st.chat_message("assistant"):
            # Dynamically restore for CURRENT role
            live_restored = vault.execute_sql_restore(m["model_reply"], sid, role)
            st.markdown(live_restored)
            with st.expander("Raw model output (placeholders intact)"):
                st.code(m["model_reply"], language="text")
            st.caption(f"{m['latency_ms']} ms | {m['tokens_per_sec']} tok/s | Role: `{role}`")

    # ── Chat input bar ───────────────────────────────────────────────
    user_in = st.chat_input("Ask anything...")
    if user_in:
        if not msgs:
            vault.conn.execute("UPDATE chat_conversations SET title=? WHERE id=?",(user_in[:30],cid))
            vault.conn.commit()
        sid, san, rep, rest, eng, route, lat, tps = run_pipeline(user_in)
        vault.add_chat_turn(cid, sid, user_in, san, rep, rest, eng, route, lat, tps)
        st.rerun()

# ═══════════════════════════════════════════════════════════════════════
# TAB 2 — BENCHMARKS
# ═══════════════════════════════════════════════════════════════════════
with tab_bench:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Regex vs SQLite Vault Recall")
        if st.button("Run Typo Benchmark"):
            r = run_trust_benchmark(vault, fuzz_t)
            st.metric("Regex Recall", f"{r['naive_recall_pct']}%")
            st.metric("Vault Recall", f"{r['vault_recall_pct']}%")
            st.dataframe(pd.DataFrame(r["details"]), use_container_width=True)
    with c2:
        st.markdown("#### SLM Coherence Suite")
        if st.button("Run Coherence"):
            s = run_llm_coherence_suite(vault, router, sel_model_id, fuzz_t)
            st.metric("Placeholder Survival", f"{s['avg_placeholder_survival_pct']}%")
            st.metric("Coherence", f"{s['avg_coherence_score_pct']}%")
            st.metric("Round-Trip Restore", f"{s['avg_roundtrip_restore_pct']}%")
            st.dataframe(pd.DataFrame(s["rows"]), use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════
# TAB 3 — AUDIT & TABLES
# ═══════════════════════════════════════════════════════════════════════
with tab_audit:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("##### sensitive_baseline")
        st.dataframe(pd.DataFrame([dict(r) for r in vault.conn.execute("SELECT * FROM sensitive_baseline").fetchall()]), use_container_width=True)
    with c2:
        st.markdown("##### assurance_audit_log")
        rows = vault.conn.execute("SELECT * FROM assurance_audit_log ORDER BY id DESC LIMIT 30").fetchall()
        df = pd.DataFrame([dict(r) for r in rows])
        st.dataframe(df, use_container_width=True)
        if not df.empty:
            st.download_button("Export Audit CSV", df.to_csv(index=False).encode(), "audit_log.csv", "text/csv")
    st.markdown("##### chat_messages (persisted in SQLite)")
    st.dataframe(pd.DataFrame([dict(r) for r in vault.conn.execute("SELECT id,conversation_id,session_id,redaction_engine,route_policy,latency_ms,created_at FROM chat_messages ORDER BY created_at DESC LIMIT 20").fetchall()]), use_container_width=True)

# ═══════════════════════════════════════════════════════════════════════
# TAB 4 — DOCS
# ═══════════════════════════════════════════════════════════════════════
with tab_docs:
    try:
        with open("UNDER_THE_HOOD.md", encoding="utf-8") as f:
            st.markdown(f.read(), unsafe_allow_html=True)
    except FileNotFoundError:
        st.info("Place UNDER_THE_HOOD.md in the project directory.")
