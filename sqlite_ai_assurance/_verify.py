from vault_engine import SQLiteAssuredVault
from llm_router import AssuredHybridRouter

v = SQLiteAssuredVault("assured_vault.db")
v.seed_domain_baselines("ALL")
r = AssuredHybridRouter()
v.seed_default_conversations_if_empty(r)

tables = [row[0] for row in v.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("Tables:", tables)
print("Baselines:", v.conn.execute("SELECT COUNT(*) FROM sensitive_baseline").fetchone()[0])
print("Convos:", v.conn.execute("SELECT COUNT(*) FROM chat_conversations").fetchone()[0])
print("Messages:", v.conn.execute("SELECT COUNT(*) FROM chat_messages").fetchone()[0])
print("Tokens:", v.conn.execute("SELECT COUNT(*) FROM token_vault").fetchone()[0])
print("Audit:", v.conn.execute("SELECT COUNT(*) FROM assurance_audit_log").fetchone()[0])
