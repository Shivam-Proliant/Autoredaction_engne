# File: vault_engine.py
import sqlite3
import math
import re
import time
import uuid
from typing import Tuple, List, Dict, Any

try:
    from rapidfuzz.distance import DamerauLevenshtein
    HAS_RAPIDFUZZ = True
except ImportError:
    from difflib import SequenceMatcher
    HAS_RAPIDFUZZ = False


# =====================================================================
# 1. NON-LLM ALGORITHMS: SPELLING SIMILARITY, SOUNDEX & SHANNON ENTROPY
# =====================================================================

def spelling_similarity(word1: str, word2: str) -> float:
    """
    Calculates normalized spelling similarity (0.0 to 1.0).
    Uses Damerau-Levenshtein (catches human character transpositions like 'Smtih' -> 'Smith').
    """
    w1, w2 = word1.lower().strip(), word2.lower().strip()
    if not w1 or not w2:
        return 0.0
    if w1 == w2:
        return 1.0
    if HAS_RAPIDFUZZ:
        return DamerauLevenshtein.normalized_similarity(w1, w2)
    return SequenceMatcher(None, w1, w2).ratio()


def soundex(word: str) -> str:
    """
    Phonetic algorithm for indexing names by sound as pronounced in English.
    Catches phonetic human typos (e.g., 'Sinoptix' vs 'Synoptix', 'Jon' vs 'John').
    """
    word = re.sub(r'[^a-zA-Z]', '', word.upper())
    if not word:
        return "0000"
    first_letter = word[0]
    mapping = {
        'B': '1', 'F': '1', 'P': '1', 'V': '1',
        'C': '2', 'G': '2', 'J': '2', 'K': '2', 'Q': '2', 'S': '2', 'X': '2', 'Z': '2',
        'D': '3', 'T': '3',
        'L': '4',
        'M': '5', 'N': '5',
        'R': '6'
    }
    encoded = [first_letter]
    for char in word[1:]:
        digit = mapping.get(char, '0')
        if digit != '0' and digit != encoded[-1]:
            encoded.append(digit)
    return ("".join(encoded) + "000")[:4]


def shannon_entropy(text: str) -> float:
    """
    Calculates Shannon entropy (bits per character) to catch unstructured secrets,
    API keys, bearer tokens, and passwords without needing dictionary matches.
    """
    if not text:
        return 0.0
    length = len(text)
    freqs = {}
    for ch in text:
        freqs[ch] = freqs.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freqs.values())


def looks_like_secret_credential(token: str, entropy_threshold: float = 3.65) -> bool:
    """
    Classifier combining character-class diversity + Shannon entropy to avoid false positives
    on normal long English words while catching API keys and passwords.
    """
    if len(token) < 10:
        return False
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_symbol = any(c in "_-!@#$%^&*+=~" for c in token)
    class_count = sum([has_upper, has_lower, has_digit, has_symbol])

    # Common secret prefixes
    secret_prefixes = ("sk-", "pk_", "ghp_", "akia", "eyj", "xoxb-", "bearer_")
    if token.lower().startswith(secret_prefixes):
        return True

    if class_count >= 3 and shannon_entropy(token) >= entropy_threshold:
        return True
    return False


# Structured Regex Baselines for UK & Enterprise Entities
REGEX_BASELINES = {
    "EMAIL": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"),
    "UK_NI_NUMBER": re.compile(r"^[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]$", re.IGNORECASE),
    "IPV4_ADDR": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "PHONE_NUM": re.compile(r"^(?:\+44|0)7\d{9}$"),
}


# =====================================================================
# 2. SQLITE ASSURED VAULT CLASS & NATIVE SQL FUNCTIONS
# =====================================================================

class SQLiteAssuredVault:
    def __init__(self, db_path: str = "assured_vault.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._seed_default_baselines()
        self._register_sql_functions()

    def _init_schema(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS sensitive_baseline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            baseline_value TEXT NOT NULL UNIQUE,
            phonetic_code TEXT NOT NULL,
            sensitivity_level TEXT DEFAULT 'CONFIDENTIAL' -- 'PII', 'CONFIDENTIAL', 'CRITICAL_SECRET'
        );

        CREATE TABLE IF NOT EXISTS token_vault (
            session_id TEXT NOT NULL,
            placeholder TEXT NOT NULL,
            raw_value TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            match_method TEXT NOT NULL, -- 'EXACT', 'FUZZY_SPELLING', 'PHONETIC', 'REGEX', 'HIGH_ENTROPY'
            similarity_score REAL NOT NULL,
            sensitivity_level TEXT NOT NULL,
            created_at REAL NOT NULL,
            PRIMARY KEY (session_id, placeholder)
        );

        CREATE TABLE IF NOT EXISTS grey_zone_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            user_word TEXT NOT NULL,
            matched_baseline TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            similarity_score REAL NOT NULL,
            status TEXT DEFAULT 'PENDING_HUMAN_REVIEW'
        );

        CREATE TABLE IF NOT EXISTS assurance_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            original_length INTEGER,
            redacted_count INTEGER,
            grey_zone_count INTEGER,
            max_sensitivity TEXT,
            recommended_route TEXT, -- 'CLOUD_API_SAFE' or 'LOCAL_RUST_ENCLAVE'
            processing_ms REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
        self.conn.commit()

    def _seed_default_baselines(self):
        default_entities = [
            ("CLIENT_NAME", "Synoptix", "CONFIDENTIAL"),
            ("CLIENT_NAME", "NetworkRail", "CONFIDENTIAL"),
            ("PERSON_NAME", "Callum", "PII"),
            ("PERSON_NAME", "Cockburn", "PII"),
            ("PERSON_NAME", "Alexander", "PII"),
            ("PROJECT_CODE", "LookoutEdge", "CRITICAL_SECRET"),
            ("PROJECT_CODE", "TridentNaval", "CRITICAL_SECRET"),
            ("DEFENCE_CLEARANCE", "NATO-SECRET", "CRITICAL_SECRET"),
            ("LOCATION_SITE", "BristolBusinessPark", "PII"),
            # Multi-Domain Enterprise Baselines (Credit Control, HR, DevOps)
            ("APPLICANT_NAME", "Priya", "PII"),
            ("APPLICANT_NAME", "Patel", "PII"),
            ("POSTAL_CODE", "BS16", "PII"),
            ("POSTAL_CODE", "1QY", "PII"),
            ("INSTITUTION_NAME", "OxfordUniversity", "PII"),
            ("DATABASE_HOST", "core-banking-db.internal", "CRITICAL_SECRET"),
        ]
        cur = self.conn.cursor()
        for etype, val, level in default_entities:
            cur.execute(
                "INSERT OR IGNORE INTO sensitive_baseline (entity_type, baseline_value, phonetic_code, sensitivity_level) VALUES (?, ?, ?, ?)",
                (etype, val, soundex(val), level)
            )
        self.conn.commit()

    def seed_domain_baselines(self, domain: str = "ALL"):
        """Pre-populates domain-specific protected baselines to eliminate hardcoding."""
        domains = {
            "FINANCE_CREDIT": [
                ("APPLICANT_NAME", "Jamal", "PII"),
                ("APPLICANT_NAME", "Washington", "PII"),
                ("APPLICANT_NAME", "Priya", "PII"),
                ("APPLICANT_NAME", "Patel", "PII"),
                ("PROTECTED_ATTR", "SingleMother", "PII"),
                ("POSTAL_CODE", "BS16", "PII"),
                ("POSTAL_CODE", "1QY", "PII"),
                ("POSTAL_CODE", "E1 6AN", "PII"),
            ],
            "DEVOPS_SRE": [
                ("SERVICE_NAME", "PaymentGatewayService", "CONFIDENTIAL"),
                ("DATABASE_HOST", "prod-sql-cluster.aws.internal", "CRITICAL_SECRET"),
                ("INTERNAL_DOMAIN", "corp.synoptix.io", "CONFIDENTIAL"),
            ],
            "BLIND_HR": [
                ("CANDIDATE_NAME", "Muhammad", "PII"),
                ("CANDIDATE_NAME", "Al-Mansoor", "PII"),
                ("INSTITUTION_NAME", "OxfordUniversity", "PII"),
                ("INSTITUTION_NAME", "CambridgeUniversity", "PII"),
                ("GRAD_YEAR", "ClassOf2015", "PII"),
            ]
        }
        to_add = []
        if domain == "ALL":
            for d in domains.values():
                to_add.extend(d)
        elif domain in domains:
            to_add.extend(domains[domain])

        for etype, val, level in to_add:
            self.add_baseline(etype, val, level)

    def add_baseline(self, entity_type: str, value: str, sensitivity_level: str = "CONFIDENTIAL"):
        self.conn.execute(
            "INSERT OR IGNORE INTO sensitive_baseline (entity_type, baseline_value, phonetic_code, sensitivity_level) VALUES (?, ?, ?, ?)",
            (entity_type.upper(), value.strip(), soundex(value), sensitivity_level)
        )
        self.conn.commit()

    def redact_text(
        self,
        prompt_text: str,
        session_id: str = "default_session",
        fuzzy_threshold: float = 0.80,
        grey_zone_floor: float = 0.68,
        entropy_threshold: float = 3.65
    ) -> str:
        """
        Core SQLite UDF: Scans input text using 3 tiers (Regex/Exact, Fuzzy/Phonetic Spelling, Entropy)
        and replaces sensitive tokens with semantic placeholders without wrecking LLM context.
        """
        start_t = time.perf_counter()
        cur = self.conn.cursor()
        baselines = cur.execute(
            "SELECT entity_type, baseline_value, phonetic_code, sensitivity_level FROM sensitive_baseline"
        ).fetchall()

        # Split preserving whitespace and punctuation attachment
        tokens = re.findall(r'\S+|\s+', prompt_text)
        output_tokens = []
        redacted_count = 0
        grey_zone_count = 0
        max_sensitivity = "PUBLIC"
        sensitivity_rank = {"PUBLIC": 0, "PII": 1, "CONFIDENTIAL": 2, "CRITICAL_SECRET": 3}

        for idx, tok in enumerate(tokens):
            if tok.isspace():
                output_tokens.append(tok)
                continue

            # Separate leading/trailing punctuation from the core token
            m = re.match(r'^([^\w@+-]*)(.*?)([^\w@+-]*)$', tok)
            prefix, clean_tok, suffix = m.groups() if m else ("", tok, "")

            if not clean_tok or len(clean_tok) < 3:
                output_tokens.append(tok)
                continue

            matched_info = None

            # --- TIER 1A: Structured Regex Match ---
            for r_type, pattern in REGEX_BASELINES.items():
                if pattern.match(clean_tok):
                    matched_info = (r_type, "REGEX", 1.0, "PII")
                    break

            # --- TIER 1B & TIER 2: Exact, Fuzzy Spelling & Phonetic Baseline Match ---
            if not matched_info:
                best_sim = 0.0
                best_row = None
                clean_soundex = soundex(clean_tok)

                for row in baselines:
                    sim = spelling_similarity(clean_tok, row["baseline_value"])
                    # Boost score slightly if phonetic Soundex matches and length is close
                    if clean_soundex == row["phonetic_code"] and abs(len(clean_tok) - len(row["baseline_value"])) <= 2:
                        sim = max(sim, 0.84)

                    if sim > best_sim:
                        best_sim = sim
                        best_row = row

                if best_row and best_sim >= fuzzy_threshold:
                    method = "EXACT" if best_sim == 1.0 else "FUZZY_SPELLING"
                    matched_info = (
                        best_row["entity_type"],
                        method,
                        round(best_sim, 3),
                        best_row["sensitivity_level"]
                    )
                elif best_row and grey_zone_floor <= best_sim < fuzzy_threshold:
                    # Log Human-in-the-Loop Grey Zone alert for borderline typos
                    grey_zone_count += 1
                    cur.execute(
                        """INSERT INTO grey_zone_alerts
                        (session_id, user_word, matched_baseline, entity_type, similarity_score)
                        VALUES (?, ?, ?, ?, ?)""",
                        (session_id, clean_tok, best_row["baseline_value"], best_row["entity_type"], round(best_sim, 3))
                    )

            # --- TIER 3: Unstructured Credential / High-Entropy Detector ---
            if not matched_info and looks_like_secret_credential(clean_tok, entropy_threshold):
                ent = shannon_entropy(clean_tok)
                matched_info = ("SECRET_CREDENTIAL", "HIGH_ENTROPY", round(min(ent / 5.0, 0.99), 3), "CRITICAL_SECRET")

            # --- APPLY TOKENISATION IF MATCHED ---
            if matched_info:
                etype, method, score, sens_level = matched_info
                redacted_count += 1
                placeholder = f"{{{{{etype}_{redacted_count:02d}}}}}"

                if sensitivity_rank.get(sens_level, 0) > sensitivity_rank.get(max_sensitivity, 0):
                    max_sensitivity = sens_level

                cur.execute(
                    """INSERT OR REPLACE INTO token_vault
                    (session_id, placeholder, raw_value, entity_type, match_method, similarity_score, sensitivity_level, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (session_id, placeholder, clean_tok, etype, method, score, sens_level, time.time())
                )
                output_tokens.append(f"{prefix}{placeholder}{suffix}")
            else:
                output_tokens.append(tok)

        elapsed_ms = round((time.perf_counter() - start_t) * 1000.0, 3)
        recommended_route = "LOCAL_RUST_ENCLAVE" if max_sensitivity == "CRITICAL_SECRET" else "CLOUD_API_SAFE"

        cur.execute(
            """INSERT INTO assurance_audit_log
            (session_id, original_length, redacted_count, grey_zone_count, max_sensitivity, recommended_route, processing_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, len(prompt_text), redacted_count, grey_zone_count, max_sensitivity, recommended_route, elapsed_ms)
        )
        self.conn.commit()
        return "".join(output_tokens)

    def restore_text(self, ai_response: str, session_id: str = "default_session", user_role: str = "ADMIN") -> str:
        """
        Core SQLite UDF: Detokenises placeholders back to original credentials/metadata
        ONLY if the user_role has clearance for that sensitivity_level.
        """
        cur = self.conn.cursor()
        rows = cur.execute(
            "SELECT placeholder, raw_value, sensitivity_level FROM token_vault WHERE session_id = ?",
            (session_id,)
        ).fetchall()

        role_clearance = {
            "ADMIN": {"PUBLIC", "PII", "CONFIDENTIAL", "CRITICAL_SECRET"},
            "ANALYST": {"PUBLIC", "PII", "CONFIDENTIAL"},
            "EXTERNAL_USER": {"PUBLIC"}
        }
        allowed_levels = role_clearance.get(user_role.upper(), {"PUBLIC"})

        restored = ai_response
        for r in rows:
            if r["sensitivity_level"] in allowed_levels:
                restored = restored.replace(r["placeholder"], r["raw_value"])
            else:
                restored = restored.replace(
                    r["placeholder"],
                    f"[ACCESS_DENIED:{r['sensitivity_level']}]"
                )
        return restored

    def _register_sql_functions(self):
        """Registers functions so they can be executed inside native SQLite SELECT queries."""
        self.conn.create_function("ai_redact", 3, lambda text, sess, thresh: self.redact_text(text, sess, float(thresh)))
        self.conn.create_function("ai_restore", 3, lambda text, sess, role: self.restore_text(text, sess, role))

    def execute_sql_redact(self, prompt_text: str, session_id: str, fuzzy_threshold: float = 0.80) -> str:
        """Demonstrates calling the assurance layer via pure SQL."""
        cur = self.conn.cursor()
        res = cur.execute("SELECT ai_redact(?, ?, ?)", (prompt_text, session_id, fuzzy_threshold)).fetchone()
        return res[0] if res else prompt_text

    def execute_sql_restore(self, response_text: str, session_id: str, user_role: str = "ADMIN") -> str:
        """Demonstrates calling restoration via pure SQL."""
        cur = self.conn.cursor()
        res = cur.execute("SELECT ai_restore(?, ?, ?)", (response_text, session_id, user_role)).fetchone()
        return res[0] if res else response_text
