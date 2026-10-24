# Under the Hood: Assured AI Redaction Workbench

This guide explains how to understand, extend, run, and deploy the deterministic redaction MVP. It is written for developers implementing the project in their own environment.

## 1. What the MVP does

The workbench accepts text, scans it when the user presses **Run scan**, replaces recognized sensitive spans with stable-looking semantic placeholders, and saves the redacted output and token mappings in a local SQLite database. The browser displays the detected spans, scan measurements, and a mapping table. Original matched values are masked in the table until **Reveal originals** is selected.

The original complete input is not stored. Original matched values are stored in the local mapping table to support the reveal workflow. The database is not encrypted by this MVP; protect the machine and the database file accordingly.

The Local LLM control is intentionally disabled. There is no local model, cloud inference, or simulated response path in this app. Scan results come from the real deterministic algorithms described below.

## 2. Project layout

```text
assured_ai_mvp/
├── app.py                  # stdlib HTTP API, SQLite schema, and local server
├── engine.py               # regex, typo, phonetic, and entropy detection
├── assured_ai_mvp.sqlite3  # created on first start; local persistent data
├── static/
│   ├── index.html           # workbench structure
│   ├── styles.css           # responsive light UI
│   └── app.js               # browser interactions and API client
├── README.md                # short start guide
└── UNDER_THE_HOOD.md        # this implementation and deployment guide
```

Python's standard library is sufficient. No package installation, Node build, model download, or outbound service is required.

## 3. Request and data flow

1. The browser sends the submitted text to `POST /api/scan` on the local server.
2. `app.py` loads protected terms from SQLite and calls `RedactionEngine.scan()` in `engine.py`.
3. The scanner finds structured patterns, protected-term matches, and likely secrets; it selects non-overlapping spans and replaces them with placeholders.
4. The server writes scan metadata, the redacted text, and the per-match token mappings in one SQLite connection, then returns the scan for display.
5. By default, mapping API responses replace every original value with `[REDACTED]`. The separate reveal endpoint returns the stored originals only after the user enables the reveal control.

The app binds to `127.0.0.1:8765`, so it is available only from the same machine by default. HTTP request logging does not include request bodies.

## 4. Detection algorithms

### Structured patterns

Precompiled regular expressions find email addresses, IPv4 addresses, UK National Insurance numbers, UK mobile numbers, common API key formats, and bearer tokens. IPv4 candidates are checked so each octet is in the `0–255` range. Structured matches take priority when spans overlap.

### Protected terms, typos, and phonetics

The `protected_terms` table holds a phrase, entity type, and sensitivity. The UI can add and delete entries. Terms are matched over full word spans, so phrases and punctuation-separated values can be handled as a unit. A normalized Damerau–Levenshtein similarity score catches spelling errors and transpositions. A Soundex comparison adds phonetic matching for English-like names. Strong matches are classified as exact, fuzzy, or phonetic. Borderline scores are also redacted and marked **Review** so uncertain text does not pass through as clean output.

Terms with more words are considered first. Once a candidate has claimed a span, overlapping candidates are dropped to avoid duplicate placeholders.

### Entropy-based credential detection

Remaining token-like strings are evaluated using Shannon entropy and character-class diversity. Known secret prefixes are handled directly. This is a heuristic and can miss credentials whose format is unlike the covered patterns, or flag unusual non-secret strings. Review the detected output before using it.

### Placeholder and sensitivity fields

Each accepted match receives an ordered placeholder such as `{{PERSON_NAME_01}}`. The mapping stores the original matched span, detection method, similarity score, sensitivity, review flag, and source offsets. The scan record stores the redacted text, source length, number of matches, review count, and processing time; it does not store the full source text.

## 5. SQLite tables

- `protected_terms`: user-managed detection terms. Useful fields: `value`, `entity_type`, and `sensitivity`.
- `scans`: one row per submitted scan. `redacted_text` is the persisted output and `id` identifies the scan.
- `redaction_mappings`: one row per placeholder, linked to a scan. `raw_value` contains the original matched text and is sensitive data.

SQLite creates the database and seeds example terms at first app start. Back up the database only to a location with access controls. To start with a fresh local database, stop the server, move or delete `assured_ai_mvp.sqlite3`, and start the app again. This removes scan history, mappings, and custom terms.

## 6. Local development and start

Requirements: Python 3.10 or newer.

From a terminal in this directory:

```powershell
python app.py
```

Open <http://127.0.0.1:8765>. Stop the process with Ctrl+C. The database file is created beside `app.py`.

### Start both apps in this repository

The repository also contains the original Streamlit prototype in `sqlite_ai_assurance/`. The two apps are separate and use separate SQLite databases. To start both, open two terminals from the repository root.

Terminal 1 — original Streamlit prototype (Windows PowerShell):

```powershell
cd sqlite_ai_assurance
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\streamlit.exe run app.py --server.address 127.0.0.1 --server.port 8501
```

If that virtual environment already exists, skip the `venv` creation and dependency installation steps. Open <http://127.0.0.1:8501>.

Terminal 2 — standalone deterministic MVP:

```powershell
cd assured_ai_mvp
python app.py
```

Open <http://127.0.0.1:8765>. Keep both processes running in their terminals. Stop either app with Ctrl+C. For macOS or Linux, use `python3 -m venv venv`, `./venv/bin/python -m pip install -r requirements.txt`, and `./venv/bin/streamlit run app.py --server.address 127.0.0.1 --server.port 8501` for the prototype. The MVP can be started with `python3 app.py`.

For development, edit `engine.py` for scanning behavior, `app.py` for the API and persistence, and the files in `static/` for the UI. Restart the Python process after changing backend files; refresh the browser after frontend changes. The original Streamlit prototype is maintained separately and is not a dependency of this MVP.

## 7. Local API

All API routes are served from the same origin as the UI:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Local server and engine status |
| GET | `/api/terms` | List protected terms |
| POST | `/api/terms` | Add a term (`value`, `entity_type`, `sensitivity`) |
| DELETE | `/api/terms/{id}` | Delete a protected term |
| POST | `/api/scan` | Scan JSON `{ "text": "..." }` |
| GET | `/api/scans` | Read the latest 50 saved scans and mappings, with originals masked |
| GET | `/api/scans/{id}` | Read a saved scan with originals masked |
| GET | `/api/scans/{id}/reveal` | Return mapping originals for the explicit reveal workflow |

The scan endpoint accepts up to 100,000 characters. Protected terms are limited to 120 characters. Invalid or empty input returns a JSON error with an appropriate HTTP status.

## 8. Deployment

### Private single-machine use (recommended for this MVP)

Run the server on the machine where the text is being scanned and keep the bind address at `127.0.0.1`. Do not expose the port through a router, firewall, tunnel, or public reverse proxy. Restrict file-system access to the project directory and its SQLite database. Back up that database only if the backup location is protected to the same standard as the originals it contains.

For a team deployment, run one private instance per user or host it on an access-controlled internal machine only after adding authentication, HTTPS, encrypted storage, backups, and an agreed retention/deletion policy. The current app has no user accounts, authorization, encryption-at-rest, or multi-tenant isolation. Its reveal endpoint is intended for the same local browser and is not an authorization boundary.

### Linux service example for a private host

Use a dedicated operating-system account and a private application directory. Example systemd unit (adjust paths and account names):

```ini
[Unit]
Description=Assured AI Redaction Workbench
After=network.target

[Service]
Type=simple
User=redaction
Group=redaction
WorkingDirectory=/opt/assured-ai/assured_ai_mvp
ExecStart=/usr/bin/python3 /opt/assured-ai/assured_ai_mvp/app.py
Restart=on-failure
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

The current server listens on loopback port 8765. Keep it private. If you put a reverse proxy in front of it for internal use, configure TLS and authentication at the proxy, limit network access, and review the security limitations above before enabling access for more than one trusted user. Do not publish this unauthenticated server directly to the internet.

### Windows private-machine startup

Use Task Scheduler or a managed service wrapper to start `python.exe` with `app.py`, with the working directory set to this folder and the service account restricted to the project directory. Keep Windows Firewall rules closed to inbound port 8765. Run it in a dedicated terminal for development and stop with Ctrl+C.

## 9. Extending safely

- Add structured detectors as compiled patterns in `PATTERNS` in `engine.py`, including realistic positive and negative examples.
- Keep all span offsets relative to the original submitted text. Add overlap behavior deliberately; the current selection keeps the highest-priority, longest non-overlapping candidates.
- Add classifications to the allowed sensitivity values in both the UI and API validation if a new sensitivity tier is required.
- If implementing restoration, enforce authorization on the server and do not treat a hidden UI value as access control.
- If adding any model provider, send only the redacted output and clearly distinguish real inference from the current disabled Local LLM control.
- Before claiming regulatory or zero-leak guarantees, build and run a maintained test suite for false positives, false negatives, overlap cases, malformed input, persistence, and access control. The current scanner is an MVP heuristic, not a certification.
