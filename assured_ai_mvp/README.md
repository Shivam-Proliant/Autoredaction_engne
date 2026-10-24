# PromptVeil Redaction Workbench

A local-only redaction workbench with a deterministic scanning engine and SQLite persistence. The browser app uses algorithms only. The packaged desktop app can additionally use the Qwen2.5-0.5B-Instruct model cached on this laptop, fully offline.

See [UNDER_THE_HOOD.md](UNDER_THE_HOOD.md) for architecture, detection details, local implementation guidance, and deployment instructions.

## Run

Requires Python 3.10 or newer. No packages need to be installed.

```powershell
cd assured_ai_mvp
python app.py
```

Open <http://127.0.0.1:8765>. Stop the server with Ctrl+C. The SQLite database is created at `assured_ai_mvp.sqlite3` in this folder.

## Windows desktop application

To build a single-window desktop app, open PowerShell in this folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build_windows.ps1
```

The executable is written to `dist\PromptVeil-RedactionWorkbench-1.2.6\PromptVeil-RedactionWorkbench-1.2.6.exe`. Tier 1 works without a Python install. Tiers 2 and 3 use the locally cached Qwen2.5-0.5B-Instruct model through an installed Python runtime with PyTorch and Transformers; they stay disabled if the model or runtime is missing. Model inference runs offline on CPU and only in this desktop app. The SQLite vault is saved under `%LOCALAPPDATA%\AssuredAI\RedactionWorkbench`. Building requires Python 3.10+ and network access to install packaging tools. The Microsoft Edge WebView2 Runtime must be present.

## What it detects

- Email addresses; valid IPv4/IPv6 addresses; UK postcodes and National Insurance numbers; US SSNs; UK/North American mobile numbers; UK sort codes; and Luhn-checked payment card numbers.
- Common API-key formats, bearer tokens, and custom credentials after labels such as `api_key=` or `password:`; plus high-entropy credential-like strings.
- Person names after common context cues, as well as exact protected terms, Damerau–Levenshtein spelling matches, and Soundex phonetic matches. Borderline matches are still redacted and marked for review.
- Street addresses; account numbers after cues such as `her account 7391846201` or `account number is ...`; card fragments after cues such as `card ends in 5831` or `debit card ending in 4128`; currency amounts, service names, ethnicity labels, and common UK region/city names. Account matches use `ACCOUNT_NUMBER` placeholders, explicitly identified debit/credit cards use `DEBIT_CARD`/`CREDIT_CARD`, and unspecified cards use `PAYMENT_CARD`.

Detectors can be switched individually or all together, and settings persist across restarts. Custom placeholder rules can be added or removed in the UI: enter the actual protected value and select its placeholder type. Scan results store the redacted text and token mappings in SQLite. Original matched values are masked in the UI until **Reveal originals** is enabled. The original full input is not stored.

The browser workbench and Tier 1 scan algorithmically when **Run scan** is selected. Qwen inference is limited to the packaged desktop app; Tier 2 model suggestions are marked for review and Tier 3 combines model suggestions with algorithmic detections.

## Local API

- `GET /api/health`
- `GET /api/terms`, `POST /api/terms`, `DELETE /api/terms/{id}`
- `POST /api/scan` with JSON `{ "text": "..." }`
- `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/reveal`
- `GET /api/compliance-report` — GDPR processing evidence and redacted audit metadata, without original text or matched values

The server binds to `127.0.0.1` only. Scan requests and input text are not written to application logs.
