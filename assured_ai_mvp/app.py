"""Local-only HTTP app for the PromptVeil Redaction Workbench."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from engine import DEFAULT_DETECTORS, DETECTOR_LABELS, GENERIC_LABELS, RedactionEngine


ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
if getattr(sys, "frozen", False):
    DATA_ROOT = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "AssuredAI" / "RedactionWorkbench"
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
else:
    DATA_ROOT = ROOT
DB_PATH = DATA_ROOT / "assured_ai_mvp.sqlite3"
STATIC = ROOT / "static"
DESKTOP_APP = os.environ.get("ASSURED_DESKTOP_APP") == "1"
if DESKTOP_APP:
    from local_qwen import LocalQwenRuntime

    LOCAL_QWEN = LocalQwenRuntime(ROOT / "local_qwen_worker.py", DATA_ROOT)
else:
    LOCAL_QWEN = None


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS protected_terms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL COLLATE NOCASE UNIQUE,
            entity_type TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            original_length INTEGER NOT NULL,
            redacted_text TEXT NOT NULL,
            match_count INTEGER NOT NULL,
            review_count INTEGER NOT NULL,
            processing_ms REAL NOT NULL,
            tier TEXT NOT NULL DEFAULT 'algorithmic',
            model_name TEXT NOT NULL DEFAULT ''
        )
    """)
    scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    if "tier" not in scan_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN tier TEXT NOT NULL DEFAULT 'algorithmic'")
    if "model_name" not in scan_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN model_name TEXT NOT NULL DEFAULT ''")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS redaction_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            placeholder TEXT NOT NULL,
            raw_value TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            match_method TEXT NOT NULL,
            similarity REAL NOT NULL,
            sensitivity TEXT NOT NULL,
            detector_key TEXT NOT NULL DEFAULT 'service_name',
            review_required INTEGER NOT NULL DEFAULT 0,
            span_start INTEGER NOT NULL,
            span_end INTEGER NOT NULL,
            UNIQUE(scan_id, placeholder)
        )
    """)
    mapping_columns = {row[1] for row in conn.execute("PRAGMA table_info(redaction_mappings)")}
    if "detector_key" not in mapping_columns:
        conn.execute("ALTER TABLE redaction_mappings ADD COLUMN detector_key TEXT NOT NULL DEFAULT 'service_name'")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detector_settings (
            detector_key TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.executemany(
        "INSERT OR IGNORE INTO detector_settings(detector_key, enabled) VALUES (?, ?)",
        [(key, int(enabled)) for key, enabled in DEFAULT_DETECTORS.items()],
    )
    seed = [
        ("Priya", "PERSON_NAME", "PII"),
        ("Patel", "PERSON_NAME", "PII"),
        ("Callum Cockburn", "PERSON_NAME", "PII"),
        ("Alexander", "PERSON_NAME", "PII"),
        ("Synoptix", "CLIENT_NAME", "CONFIDENTIAL"),
        ("NetworkRail", "CLIENT_NAME", "CONFIDENTIAL"),
        ("LookoutEdge", "PROJECT_CODE", "CRITICAL_SECRET"),
        ("TridentNaval", "PROJECT_CODE", "CRITICAL_SECRET"),
        ("NATO-SECRET", "DEFENCE_CLEARANCE", "CRITICAL_SECRET"),
        ("BristolBusinessPark", "LOCATION_SITE", "PII"),
        ("OxfordUniversity", "INSTITUTION_NAME", "CONFIDENTIAL"),
        ("core-banking-db.internal", "DATABASE_HOST", "CRITICAL_SECRET"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO protected_terms(value, entity_type, sensitivity) VALUES (?, ?, ?)",
        seed,
    )
    # Old UI usage sometimes saved a field label like "Name" as a protected value.
    # Field labels are detected by algorithms; dictionary entries must be actual values.
    labels = tuple(GENERIC_LABELS)
    placeholders = ",".join("?" for _ in labels)
    conn.execute(f"DELETE FROM protected_terms WHERE lower(trim(value)) IN ({placeholders})", labels)
    conn.commit()
    return conn


def fetch_scan(conn: sqlite3.Connection, scan_id: str, reveal: bool = False) -> dict | None:
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        return None
    mappings = conn.execute(
        "SELECT placeholder, raw_value, entity_type, match_method, similarity, sensitivity, detector_key, review_required, span_start, span_end "
        "FROM redaction_mappings WHERE scan_id = ? ORDER BY span_start, id",
        (scan_id,),
    ).fetchall()
    mapping_rows = [dict(row) for row in mappings]
    return {
        **dict(scan),
        "mappings": [
            {**row, "raw_value": row["raw_value"] if reveal else "[REDACTED]"}
            for row in mapping_rows
        ],
        "highlights": [
            {"start": row["span_start"], "end": row["span_end"], "placeholder": row["placeholder"],
             "entity_type": row["entity_type"], "detector": row["detector_key"],
             "review_required": bool(row["review_required"])}
            for row in mapping_rows
        ],
    }


QWEN_ENTITY_MAP = {
    "PERSON_NAME": ("PERSON_NAME", "name", "PII"), "NAME": ("PERSON_NAME", "name", "PII"),
    "ADDRESS": ("ADDRESS", "address", "PII"), "LOCATION": ("ADDRESS", "address", "PII"),
    "EMAIL": ("EMAIL", "email", "PII"), "EMAIL_ADDRESS": ("EMAIL", "email", "PII"),
    "MOBILE": ("MOBILE_NUMBER", "mobile", "PII"), "MOBILE_NUMBER": ("MOBILE_NUMBER", "mobile", "PII"),
    "PHONE": ("MOBILE_NUMBER", "mobile", "PII"), "PHONE_NUMBER": ("MOBILE_NUMBER", "mobile", "PII"),
    "IP": ("IP_ADDRESS", "ip", "PII"), "IP_ADDRESS": ("IP_ADDRESS", "ip", "PII"),
    "ACCOUNT_NUMBER": ("ACCOUNT_NUMBER", "bank_account", "CONFIDENTIAL"), "BANK_ACCOUNT": ("BANK_ACCOUNT", "bank_account", "CONFIDENTIAL"),
    "PAYMENT_CARD": ("PAYMENT_CARD", "payment_card", "CRITICAL_SECRET"), "CREDIT_CARD": ("CREDIT_CARD", "payment_card", "CRITICAL_SECRET"),
    "DEBIT_CARD": ("DEBIT_CARD", "payment_card", "CRITICAL_SECRET"),
    "API_KEY": ("SECRET_API_KEY", "api_key", "CRITICAL_SECRET"), "SECRET_API_KEY": ("SECRET_API_KEY", "api_key", "CRITICAL_SECRET"),
    "PASSWORD": ("PASSWORD", "password", "CRITICAL_SECRET"),
    "ETHNICITY": ("ETHNICITY", "ethnicity", "PII"), "REGION": ("REGION", "region", "PII"),
    "SERVICE_NAME": ("SERVICE_NAME", "service_name", "CONFIDENTIAL"),
    "FINANCIAL_AMOUNT": ("FINANCIAL_AMOUNT", "amount", "CONFIDENTIAL"), "AMOUNT": ("FINANCIAL_AMOUNT", "amount", "CONFIDENTIAL"),
}


def merge_qwen_matches(text: str, base_result: dict, entities: list[dict], enabled: dict[str, bool]) -> dict:
    matches = list(base_result["matches"])
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        value = entity.get("value", entity.get("text"))
        if (not isinstance(value, str) or value not in text) and isinstance(entity.get("entity"), str):
            value = entity["entity"]
        entity_key = re.sub(r"[^A-Z0-9]+", "_", str(entity.get("type", entity.get("entity_type", ""))).upper()).strip("_")
        spec = QWEN_ENTITY_MAP.get(entity_key)
        if not isinstance(value, str) or not spec:
            continue
        value = value.strip()
        if len(value) < 2 or len(value) > 200 or value.casefold() in GENERIC_LABELS:
            continue
        entity_type, detector, sensitivity = spec
        if not enabled.get(detector, True):
            continue
        search_from = 0
        while True:
            start = text.find(value, search_from)
            if start < 0:
                break
            end = start + len(value)
            search_from = end
            if any(start < found["end"] and end > found["start"] for found in matches):
                continue
            matches.append({
                "start": start, "end": end, "entity_type": entity_type,
                "sensitivity": sensitivity, "match_method": "QWEN_LOCAL_CLASSIFIER",
                "similarity": 0.7, "review_required": True, "detector": detector,
            })

    matches.sort(key=lambda item: item["start"])
    for index, item in enumerate(matches, 1):
        item["placeholder"] = "{{" + re.sub(r"[^A-Z0-9]+", "_", item["entity_type"].upper()).strip("_") + f"_{index:02d}" + "}}"
        item["raw_value"] = text[item["start"]:item["end"]]
    pieces, cursor = [], 0
    for item in matches:
        pieces.extend((text[cursor:item["start"]], item["placeholder"]))
        cursor = item["end"]
    pieces.append(text[cursor:])
    base_result["redacted_text"] = "".join(pieces)
    base_result["matches"] = matches
    base_result["review_count"] = sum(bool(item["review_required"]) for item in matches)
    return base_result


class Handler(BaseHTTPRequestHandler):
    server_version = "AssuredRedactionMVP/1.0"

    def log_message(self, fmt: str, *args) -> None:
        # Request paths are harmless; request bodies (which may contain PII) are never logged.
        super().log_message(fmt, *args)

    def _json(self, status: int, data: object) -> None:
        encoded = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _body(self) -> dict:
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size > 1_000_000:
                raise ValueError("Request is too large (1 MB maximum).")
            data = json.loads(self.rfile.read(size) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")
            return data
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Request body must be valid JSON.") from None

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route == "/api/terms":
            with connect_db() as conn:
                terms = [dict(row) for row in conn.execute(
                    "SELECT id, value, entity_type, sensitivity FROM protected_terms ORDER BY value COLLATE NOCASE"
                )]
            return self._json(200, {"terms": terms})
        if route == "/api/detectors":
            with connect_db() as conn:
                states = {row["detector_key"]: bool(row["enabled"]) for row in conn.execute("SELECT detector_key, enabled FROM detector_settings")}
            return self._json(200, {"detectors": [
                {"key": key, "label": label, "enabled": states.get(key, True)}
                for key, label in DETECTOR_LABELS.items()
            ]})
        if route == "/api/scans":
            with connect_db() as conn:
                rows = conn.execute("SELECT id FROM scans ORDER BY created_at DESC, rowid DESC LIMIT 50").fetchall()
                scans = [fetch_scan(conn, row["id"]) for row in rows]
            return self._json(200, {"scans": scans})
        if route == "/api/compliance-report":
            with connect_db() as conn:
                rows = conn.execute("SELECT id FROM scans ORDER BY created_at, rowid").fetchall()
                scans = []
                for row in rows:
                    saved = fetch_scan(conn, row["id"])
                    scans.append({
                        "id": saved["id"],
                        "created_at": saved["created_at"],
                        "original_length": saved["original_length"],
                        "match_count": saved["match_count"],
                        "review_count": saved["review_count"],
                        "processing_ms": saved["processing_ms"],
                        "tier": saved["tier"],
                        "model_name": saved["model_name"] or None,
                        "mappings": [{key: mapping[key] for key in (
                            "placeholder", "entity_type", "match_method", "similarity",
                            "sensitivity", "detector_key", "review_required", "span_start", "span_end",
                        )} for mapping in saved["mappings"]],
                    })
            report = {
                "report_title": "PromptVeil GDPR Processing Evidence Report",
                "report_type": "GDPR processing evidence; not a certification of legal compliance",
                "schema_version": 2,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "storage": "Local SQLite",
                "gdpr_context": {
                    "purpose": "Local text scanning and redaction of sensitive information before downstream use.",
                    "data_minimisation": "Original input text is not retained. Match originals are stored locally in SQLite for mapping, but excluded from this report.",
                    "security_and_access": "This report contains redacted scan metadata only. Protect the device and its SQLite vault with appropriate access controls.",
                    "retention": "Scan history and match mappings remain in the local SQLite vault until the user removes the database or implements a retention policy.",
                    "operator_review": "Review detection output, lawful basis, purpose limitation, retention, access controls, and data-subject rights for your deployment.",
                },
                "processing": {
                    "engine": "local algorithmic detectors with optional Qwen classification",
                    "model_inference_used": any(scan["model_name"] for scan in scans),
                    "models_used": sorted({scan["model_name"] for scan in scans if scan["model_name"]}),
                },
                "privacy": {"original_input_stored": False, "matched_original_values_included": False},
                "summary": {
                    "scan_count": len(scans),
                    "redaction_count": sum(scan["match_count"] for scan in scans),
                    "review_count": sum(scan["review_count"] for scan in scans),
                    "entity_counts": {},
                },
                "scans": scans,
            }
            entity_counts = report["summary"]["entity_counts"]
            for scan in scans:
                for mapping in scan["mappings"]:
                    entity = mapping["entity_type"]
                    entity_counts[entity] = entity_counts.get(entity, 0) + 1
            return self._json(200, {"report": report})
        if route == "/api/runtime":
            model_status = LOCAL_QWEN.status() if LOCAL_QWEN else {
                "available": False, "state": "desktop_only", "model": None,
                "message": "Local model inference is available only in the packaged desktop app.",
                "device": None,
            }
            return self._json(200, {
                "desktop_app": DESKTOP_APP,
                "local_model": model_status,
                "tiers": {"algorithmic": True, "local_llm": bool(DESKTOP_APP and model_status["available"]),
                          "hybrid": bool(DESKTOP_APP and model_status["available"])},
            })
        if route.startswith("/api/scans/"):
            parts = route.strip("/").split("/")
            if len(parts) not in (3, 4):
                return self._json(404, {"error": "Scan not found."})
            reveal = len(parts) == 4 and parts[3] == "reveal"
            with connect_db() as conn:
                scan = fetch_scan(conn, parts[2], reveal=reveal)
            return self._json(200, {"scan": scan}) if scan else self._json(404, {"error": "Scan not found."})
        if route == "/api/health":
            return self._json(200, {"status": "ok", "engine": "deterministic"})
        self._static(route)

    def _static(self, route: str) -> None:
        relative = "index.html" if route == "/" else route.lstrip("/")
        target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents and target != STATIC.resolve():
            return self._json(404, {"error": "Not found."})
        if not target.is_file():
            return self._json(404, {"error": "Not found."})
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        try:
            payload = self._body()
            if route == "/api/scan":
                return self._scan(payload)
            if route == "/api/terms":
                return self._add_term(payload)
            return self._json(404, {"error": "Not found."})
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})

    def _scan(self, payload: dict) -> None:
        text = payload.get("text")
        tier = payload.get("tier", "algorithmic")
        if not isinstance(tier, str) or tier not in {"algorithmic", "local_llm", "hybrid"}:
            return self._json(400, {"error": "Choose a supported processing tier."})
        if tier != "algorithmic" and not DESKTOP_APP:
            return self._json(403, {"error": "Local Qwen inference is available only in the packaged desktop application."})
        if not isinstance(text, str) or not text.strip():
            return self._json(400, {"error": "Enter text before running a scan."})
        if len(text) > 100_000:
            return self._json(400, {"error": "Text must be 100,000 characters or fewer."})
        started = time.perf_counter()
        conn = connect_db()
        try:
            terms = [dict(row) for row in conn.execute(
                "SELECT value, entity_type, sensitivity FROM protected_terms"
            )]
            terms.sort(key=lambda item: len(item["value"]), reverse=True)
            detector_state = {row["detector_key"]: bool(row["enabled"]) for row in conn.execute("SELECT detector_key, enabled FROM detector_settings")}
            model_name = ""
            if tier == "local_llm":
                disabled_detectors = {key: False for key in DEFAULT_DETECTORS}
                result = RedactionEngine([]).scan(text, disabled_detectors)
            else:
                result = RedactionEngine(terms).scan(text, detector_state)
            if tier in {"local_llm", "hybrid"}:
                try:
                    qwen_entities = LOCAL_QWEN.classify(text)
                except ValueError as exc:
                    return self._json(400, {"error": str(exc)})
                except RuntimeError as exc:
                    return self._json(503, {"error": str(exc)})
                result = merge_qwen_matches(text, result, qwen_entities, detector_state)
                model_name = "Qwen2.5-0.5B-Instruct"
            result["processing_ms"] = round((time.perf_counter() - started) * 1000, 3)
            scan_id = uuid.uuid4().hex
            conn.execute(
                "INSERT INTO scans(id, original_length, redacted_text, match_count, review_count, processing_ms, tier, model_name) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, len(text), result["redacted_text"], len(result["matches"]), result["review_count"], result["processing_ms"], tier, model_name),
            )
            conn.executemany(
                "INSERT INTO redaction_mappings(scan_id, placeholder, raw_value, entity_type, match_method, similarity, sensitivity, detector_key, review_required, span_start, span_end) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(
                    scan_id, match["placeholder"], match["raw_value"], match["entity_type"],
                    match["match_method"], match["similarity"], match["sensitivity"], match["detector"],
                    int(match["review_required"]), match["start"], match["end"],
                ) for match in result["matches"]],
            )
            conn.commit()
            scan = fetch_scan(conn, scan_id)
            scan["highlights"] = [
                {"start": item["start"], "end": item["end"], "placeholder": item["placeholder"],
                 "entity_type": item["entity_type"], "review_required": item["review_required"]}
                for item in result["matches"]
            ]
            return self._json(200, {"scan": scan})
        finally:
            conn.close()

    def _add_term(self, payload: dict) -> None:
        value = payload.get("value")
        entity_type = payload.get("entity_type", "CUSTOM_TERM")
        sensitivity = payload.get("sensitivity", "CONFIDENTIAL")
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > 120:
            return self._json(400, {"error": "Enter a protected term of 1 to 120 characters."})
        if value.strip().casefold() in GENERIC_LABELS:
            return self._json(400, {"error": "Add an actual name or phrase (for example, Marcus Albright), not a field label such as Name, Email, or API key. Those categories are scanned automatically."})
        if not isinstance(entity_type, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,39}", entity_type):
            return self._json(400, {"error": "Entity type must contain 2–40 letters, numbers, or underscores."})
        if not isinstance(sensitivity, str) or sensitivity not in {"PII", "CONFIDENTIAL", "CRITICAL_SECRET"}:
            return self._json(400, {"error": "Choose a valid sensitivity level."})
        with connect_db() as conn:
            try:
                cur = conn.execute(
                    "INSERT INTO protected_terms(value, entity_type, sensitivity) VALUES (?, ?, ?)",
                    (value.strip(), entity_type.upper(), sensitivity),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return self._json(409, {"error": "That protected term already exists."})
            term = conn.execute(
                "SELECT id, value, entity_type, sensitivity FROM protected_terms WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
        return self._json(201, {"term": dict(term)})

    def do_DELETE(self) -> None:
        parts = urlparse(self.path).path.strip("/").split("/")
        if len(parts) != 3 or parts[:2] != ["api", "terms"]:
            return self._json(404, {"error": "Not found."})
        try:
            term_id = int(parts[2])
        except ValueError:
            return self._json(400, {"error": "Invalid term id."})
        with connect_db() as conn:
            cur = conn.execute("DELETE FROM protected_terms WHERE id = ?", (term_id,))
            conn.commit()
        return self._json(200, {"deleted": cur.rowcount == 1})

    def do_PUT(self) -> None:
        if urlparse(self.path).path != "/api/detectors":
            return self._json(404, {"error": "Not found."})
        try:
            payload = self._body()
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})
        updates = payload.get("detectors")
        if not isinstance(updates, dict) or not updates:
            return self._json(400, {"error": "Provide at least one detector setting."})
        unknown = set(updates) - set(DEFAULT_DETECTORS)
        if unknown or any(not isinstance(value, bool) for value in updates.values()):
            return self._json(400, {"error": "Detector settings must use known keys and true/false values."})
        with connect_db() as conn:
            conn.executemany(
                "INSERT INTO detector_settings(detector_key, enabled) VALUES (?, ?) "
                "ON CONFLICT(detector_key) DO UPDATE SET enabled=excluded.enabled",
                [(key, int(value)) for key, value in updates.items()],
            )
        return self._json(200, {"detectors": updates})


def create_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    connect_db().close()
    server = create_server()
    print(f"PromptVeil Redaction Workbench is running at http://127.0.0.1:{server.server_port}")
    print(f"SQLite database: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping workbench...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
