"""Desktop-only bridge to a locally cached Qwen2.5 0.5B Instruct model."""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path


MODEL_REPO = "Qwen/Qwen2.5-0.5B-Instruct"


def _model_path() -> Path | None:
    cache = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")) / "hub"
    repo = cache / "models--Qwen--Qwen2.5-0.5B-Instruct"
    try:
        revision = (repo / "refs" / "main").read_text(encoding="utf-8").strip()
        path = repo / "snapshots" / revision
    except OSError:
        return None
    return path if (path / "model.safetensors").is_file() and (path / "config.json").is_file() else None


def _python_command() -> list[str] | None:
    if not getattr(sys, "frozen", False):
        return [sys.executable]
    path_python = shutil.which("python") or shutil.which("python3")
    if path_python:
        return [path_python]
    for candidate in (Path("C:/Python314/python.exe"), Path("C:/Python313/python.exe"), Path("C:/Python312/python.exe")):
        if candidate.is_file():
            return [str(candidate)]
    return None


class LocalQwenRuntime:
    def __init__(self, worker_path: Path, data_root: Path) -> None:
        self.worker_path = worker_path
        self.data_root = data_root
        self.model_path = _model_path()
        self.python = _python_command()
        self.state = "not_loaded"
        self.error = ""
        self.process: subprocess.Popen[str] | None = None
        self.ready = threading.Event()
        self.start_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.pending: dict[str, queue.Queue[dict]] = {}
        self.pending_lock = threading.Lock()

    @property
    def available(self) -> bool:
        return bool(self.model_path and self.python and self.worker_path.is_file())

    def status(self) -> dict:
        return {
            "available": self.available,
            "state": self.state,
            "model": MODEL_REPO if self.model_path else None,
            "message": self.error or ("Qwen model and local Python runtime found." if self.available else "Qwen model files or a compatible local Python runtime were not found."),
            "device": "CPU",
        }

    def _start(self) -> None:
        with self.start_lock:
            if self.process and self.process.poll() is None:
                return
            if not self.available:
                raise RuntimeError(self.status()["message"])
            env = os.environ.copy()
            env["HF_HUB_OFFLINE"] = "1"
            env["TRANSFORMERS_OFFLINE"] = "1"
            env["HF_HUB_DISABLE_TELEMETRY"] = "1"
            self.ready.clear()
            self.state = "loading"
            self.error = ""
            self.process = subprocess.Popen(
                [*self.python, str(self.worker_path), "--model", str(self.model_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            threading.Thread(target=self._read_output, name="local-qwen-output", daemon=True).start()

    def _read_output(self) -> None:
        assert self.process and self.process.stdout
        try:
            for line in self.process.stdout:
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if message.get("event") == "ready":
                    self.state = "ready"
                    self.ready.set()
                    continue
                if message.get("event") == "error":
                    self.error = str(message.get("error", "Local Qwen failed to load."))
                    self.state = "error"
                    self.ready.set()
                    continue
                request_id = message.get("id")
                with self.pending_lock:
                    response_queue = self.pending.get(request_id)
                if response_queue:
                    response_queue.put(message)
        finally:
            if self.state not in {"stopping", "not_loaded"}:
                self.state = "error"
                self.error = self.error or "The local Qwen worker stopped unexpectedly."
                self.ready.set()
            with self.pending_lock:
                pending = list(self.pending.values())
            for response_queue in pending:
                response_queue.put({"error": self.error})

    def classify(self, text: str, timeout: int = 240) -> list[dict]:
        if len(text) > 12_000:
            raise ValueError("Local Qwen scans are limited to 12,000 characters. Use Tier 1 for longer text.")
        self._start()
        if not self.ready.wait(timeout):
            raise RuntimeError("Qwen is still loading. Try this scan again in a moment.")
        if self.state != "ready":
            raise RuntimeError(self.error or "The local Qwen model could not be loaded.")
        request_id = uuid.uuid4().hex
        response_queue: queue.Queue[dict] = queue.Queue(maxsize=1)
        with self.pending_lock:
            self.pending[request_id] = response_queue
        try:
            assert self.process and self.process.stdin
            with self.write_lock:
                self.process.stdin.write(json.dumps({"id": request_id, "text": text}, ensure_ascii=False) + "\n")
                self.process.stdin.flush()
            response = response_queue.get(timeout=timeout)
            if response.get("error"):
                raise RuntimeError(response["error"])
            return response.get("entities", [])
        except queue.Empty:
            raise RuntimeError("Local Qwen did not finish the scan in time.") from None
        finally:
            with self.pending_lock:
                self.pending.pop(request_id, None)

    def close(self) -> None:
        process = self.process
        if not process or process.poll() is not None:
            return
        self.state = "stopping"
        try:
            if process.stdin:
                process.stdin.write("{\"command\":\"stop\"}\n")
                process.stdin.flush()
            process.wait(timeout=4)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
        self.state = "not_loaded"
