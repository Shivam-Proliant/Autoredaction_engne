# Assured AI Redaction Workbench MVP

A local-only redaction workbench with a dependency-free Python backend, deterministic algorithms, and SQLite persistence. The UI is served from this app; no cloud model or local LLM is involved.

See [UNDER_THE_HOOD.md](UNDER_THE_HOOD.md) for architecture, detection details, local implementation guidance, and deployment instructions.

## Run

Requires Python 3.10 or newer. No packages need to be installed.

```powershell
cd assured_ai_mvp
python app.py
```

Open <http://127.0.0.1:8765>. Stop the server with Ctrl+C. The SQLite database is created at `assured_ai_mvp.sqlite3` in this folder.

## What it detects

- Email addresses; valid IPv4/IPv6 addresses; UK postcodes and National Insurance numbers; US SSNs; UK/North American mobile numbers; UK sort codes; and Luhn-checked payment card numbers.
- Common API-key formats, bearer tokens, and custom credentials after labels such as `api_key=` or `password:`; plus high-entropy credential-like strings.
- Person names after common context cues, as well as exact protected terms, Damerau–Levenshtein spelling matches, and Soundex phonetic matches. Borderline matches are still redacted and marked for review.
- Street addresses; account numbers after cues such as `her account 7391846201` or `account number is ...`; card fragments after cues such as `card ends in 5831` or `debit card ending in 4128`; currency amounts, service names, ethnicity labels, and common UK region/city names. Account matches use `ACCOUNT_NUMBER` placeholders, explicitly identified debit/credit cards use `DEBIT_CARD`/`CREDIT_CARD`, and unspecified cards use `PAYMENT_CARD`.

Detectors can be switched individually or all together, and settings persist across restarts. Custom placeholder rules can be added or removed in the UI: enter the actual protected value and select its placeholder type. Scan results store the redacted text and token mappings in SQLite. Original matched values are masked in the UI until **Reveal originals** is enabled. The original full input is not stored.

The Local LLM button is intentionally disabled. Scanning is algorithmic and runs only when **Run scan** is selected.

## Local API

- `GET /api/health`
- `GET /api/terms`, `POST /api/terms`, `DELETE /api/terms/{id}`
- `POST /api/scan` with JSON `{ "text": "..." }`
- `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/reveal`

The server binds to `127.0.0.1` only. Scan requests and input text are not written to application logs.
