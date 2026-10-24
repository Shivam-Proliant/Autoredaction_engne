"""Native desktop shell for the local PromptVeil workbench."""

from __future__ import annotations

import threading
import tkinter as tk
import os
from pathlib import Path
from tkinter import messagebox
import traceback

os.environ["ASSURED_DESKTOP_APP"] = "1"

from app import LOCAL_QWEN, connect_db, create_server


class DesktopApi:
    """Desktop-only native file picker for explicit report exports."""

    def __init__(self) -> None:
        self.window = None

    def save_compliance_report(self, csv_text: str, suggested_name: str) -> dict:
        if not isinstance(csv_text, str) or len(csv_text) > 10_000_000:
            return {"saved": False, "error": "The report content is invalid or too large."}
        if not isinstance(suggested_name, str) or not suggested_name.startswith("promptveil-gdpr-report-"):
            suggested_name = "promptveil-gdpr-report.csv"
        suggested_name = Path(suggested_name).name
        if not suggested_name.lower().endswith(".csv"):
            suggested_name += ".csv"
        downloads = Path.home() / "Downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        destination = downloads / suggested_name
        suffix = 2
        while destination.exists():
            destination = downloads / f"{Path(suggested_name).stem}-{suffix}.csv"
            suffix += 1
        destination.write_text(csv_text, encoding="utf-8-sig", newline="")
        return {"saved": True, "path": str(destination)}


def main() -> None:
    server = None

    def stop_server() -> None:
        if server is not None:
            threading.Thread(target=server.shutdown, name="redaction-api-shutdown", daemon=True).start()
        if LOCAL_QWEN:
            LOCAL_QWEN.close()

    try:
        import webview
        connect_db().close()
        server = create_server(0)
        threading.Thread(target=server.serve_forever, name="redaction-api", daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}/"
        desktop_api = DesktopApi()
        window = webview.create_window(
            "PromptVeil — Redaction Workbench",
            url,
            width=1440,
            height=960,
            min_size=(900, 680),
            text_select=True,
            js_api=desktop_api,
        )
        desktop_api.window = window

        window.events.closed += stop_server
        webview.start(gui="edgechromium", debug=False)
    except Exception as exc:
        from app import DATA_ROOT

        error_text = traceback.format_exc()
        try:
            (DATA_ROOT / "desktop-startup-error.log").write_text(error_text, encoding="utf-8")
        except OSError:
            pass
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "PromptVeil Workbench",
            f"The desktop app could not start.\n\n{exc}\n\nDetails are saved in the local app data folder.",
        )
    finally:
        if server:
            stop_server()
            server.server_close()


if __name__ == "__main__":
    main()
