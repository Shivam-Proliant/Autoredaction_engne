# File: sqlite_ai_assurance/trust_evaluator.py
import re
import time
from typing import Dict, Any, List
from vault_engine import SQLiteAssuredVault
from llm_router import AssuredHybridRouter

# Multi-Domain Benchmark Suite reflecting Realistic Human Workflows & Adversarial Inputs:
# 1. Credit Control / Fair Lending (Bias Mitigation)
# 2. DevOps & SRE Incident (Zero-Leak API Keys & Credentials)
# 3. Blind HR Recruitment (Algorithmic Discrimination Mitigation)
# 4. Autonomous Agentic Tool-Calling Gateway
# 5. Defence & Critical Infrastructure Enclave
BENCHMARK_SUITE = [
    (
        "Credit Review: Underwrite loan application for Priya Patel (single mother, age 32) residing at BS16 1QY with credit score 740.",
        ["Priya", "Patel", "BS16", "1QY"]
    ),
    (
        "SRE Incident: Reset database connection for Callum Cokburn at Synoptx using token sk-proj-99a8B7c6D5e4F3g2H1 and IP 192.168.1.200.",
        ["Callum", "Cokburn", "Synoptx", "sk-proj-99a8B7c6D5e4F3g2H1", "192.168.1.200"]
    ),
    (
        "Blind HR: Evaluate senior developer resume for Alexnder Cockbrn graduated OxfordUniversity 2018 at BristolBusinessPark.",
        ["Alexnder", "Cockbrn", "OxfordUniversity", "BristolBusinessPark"]
    ),
    (
        "Agentic Workflow: Execute deploy tool for LookoutEdg on NetwrkRail telemetry cluster with key ghp_8899aabbCCDDEEFF001122334455.",
        ["LookoutEdg", "NetwrkRail", "ghp_8899aabbCCDDEEFF001122334455"]
    ),
    (
        "Defence Enclave: Urgent telemetry sync for TridentNavl under NATO-SECRT clearance with auth hash X9#mK2$pL8@vQ5!zR1.",
        ["TridentNavl", "NATO-SECRT", "X9#mK2$pL8@vQ5!zR1"]
    ),
]


def naive_regex_redact(text: str, exact_list: List[str]) -> str:
    """Industry standard baseline: Only catches exact dictionary matches and basic email regex."""
    out = text
    out = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED]", out)
    for item in exact_list:
        out = out.replace(item, "[REDACTED]")
    return out


def run_trust_benchmark(vault: SQLiteAssuredVault, fuzzy_threshold: float = 0.78) -> Dict[str, Any]:
    """
    Benchmarks Standard Regex/Exact DLP vs SQLite 3-Tier Multi-Method Engine.
    """
    cur = vault.conn.cursor()
    exact_baselines = [r[0] for r in cur.execute("SELECT baseline_value FROM sensitive_baseline").fetchall()]

    total_secrets = 0
    naive_caught = 0
    sqlite_vault_caught = 0
    detailed_rows = []

    t0 = time.perf_counter()
    for idx, (prompt, ground_truth_tokens) in enumerate(BENCHMARK_SUITE):
        sess_id = f"bench_{idx}_{int(time.time()*1000)}"
        naive_out = naive_regex_redact(prompt, exact_baselines)
        vault_out = vault.execute_sql_redact(prompt, sess_id, fuzzy_threshold)

        for secret_tok in ground_truth_tokens:
            total_secrets += 1
            caught_by_naive = secret_tok not in naive_out
            caught_by_vault = secret_tok not in vault_out

            if caught_by_naive:
                naive_caught += 1
            if caught_by_vault:
                sqlite_vault_caught += 1

            detailed_rows.append({
                "Test Case": f"Scenario #{idx+1}",
                "Target / Human Typo": secret_tok,
                "Standard Regex/Exact": "CAUGHT" if caught_by_naive else "LEAKED TO API",
                "SQLite Fuzzy+Entropy Vault": "ASSURED (TOKENISED)" if caught_by_vault else "LEAKED",
            })

    total_ms = round((time.perf_counter() - t0) * 1000, 2)
    naive_recall = round((naive_caught / total_secrets) * 100, 1)
    vault_recall = round((sqlite_vault_caught / total_secrets) * 100, 1)

    return {
        "total_sensitive_entities": total_secrets,
        "naive_recall_pct": naive_recall,
        "naive_leak_rate_pct": round(100.0 - naive_recall, 1),
        "vault_recall_pct": vault_recall,
        "vault_leak_rate_pct": round(100.0 - vault_recall, 1),
        "benchmark_latency_ms": total_ms,
        "details": detailed_rows
    }


def run_llm_coherence_suite(
    vault: SQLiteAssuredVault,
    router: AssuredHybridRouter,
    selected_model_id: str,
    fuzzy_threshold: float = 0.78
) -> Dict[str, Any]:
    """
    Runs the full benchmark suite through the complete privacy & coherence round-trip:
    Raw Prompt -> SQLite ai_redact() -> Selected Local Small LLM -> SQLite ai_restore()
    Evaluates:
    1. Placeholder Survival Rate (%): Did the model preserve {{ENTITY_01}}?
    2. Semantic Coherence Score (%): Was the response structured and relevant?
    3. End-to-End Round-Trip Detokenisation (%): Did ai_restore() cleanly recover original credentials?
    4. Hardware Sustainability Telemetry: Latency (ms) & Tokens/Sec.
    """
    suite_rows = []
    survival_scores = []
    coherence_scores = []
    restoration_scores = []
    latencies = []
    engine_name = selected_model_id

    scenario_names = [
        "Credit Control (Fair Lending Bias Mitigation)",
        "DevOps SRE (Zero-Leak Secrets & Production IP)",
        "Blind HR (Anti-Discrimination CV Screening)",
        "Agentic Workflow (Tool-Calling Interceptor)",
        "Defence & Critical Infrastructure Enclave"
    ]

    for idx, (prompt, ground_truth_tokens) in enumerate(BENCHMARK_SUITE):
        sess_id = f"llm_suite_{idx}_{int(time.time()*1000)}"
        redacted_prompt = vault.execute_sql_redact(prompt, sess_id, fuzzy_threshold)

        llm_res = router.generate_response(
            redacted_prompt,
            route="LOCAL_RUST_ENCLAVE",
            selected_model_id=selected_model_id
        )
        engine_name = llm_res["engine_used"]
        ai_reply = llm_res["reply"]
        coherence_info = llm_res["coherence"]

        # Test SQLite ai_restore() round-trip restoration for ADMIN role
        restored_reply = vault.execute_sql_restore(ai_reply, sess_id, "ADMIN")

        # Verify how many preserved placeholders were cleanly restored back to their ground-truth values
        preserved_phs = coherence_info["preserved_placeholders"]
        if preserved_phs:
            unrestored_count = sum(1 for ph in preserved_phs if ph in restored_reply)
            roundtrip_pct = round(((len(preserved_phs) - unrestored_count) / len(preserved_phs)) * 100.0, 1)
        else:
            roundtrip_pct = 100.0 if not coherence_info["input_placeholders"] else 0.0

        survival_scores.append(coherence_info["placeholder_survival_pct"])
        coherence_scores.append(coherence_info["coherence_score_pct"])
        restoration_scores.append(roundtrip_pct)
        latencies.append(llm_res["latency_ms"])

        suite_rows.append({
            "Workflow Scenario": scenario_names[idx] if idx < len(scenario_names) else f"Scenario #{idx+1}",
            "Redacted Input Sent to Local Model": redacted_prompt,
            "Local Model Output (With Placeholders)": ai_reply,
            "SQLite Detokenised Output (ADMIN)": restored_reply,
            "Placeholder Survival %": f"{coherence_info['placeholder_survival_pct']}%",
            "Coherence Score %": f"{coherence_info['coherence_score_pct']}%",
            "Round-Trip Restore %": f"{roundtrip_pct}%",
            "Latency (ms)": llm_res["latency_ms"]
        })

    n = max(len(suite_rows), 1)
    return {
        "engine_tested": engine_name,
        "avg_placeholder_survival_pct": round(sum(survival_scores) / n, 1),
        "avg_coherence_score_pct": round(sum(coherence_scores) / n, 1),
        "avg_roundtrip_restore_pct": round(sum(restoration_scores) / n, 1),
        "avg_latency_ms": round(sum(latencies) / n, 1),
        "rows": suite_rows
    }
