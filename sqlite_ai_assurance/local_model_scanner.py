# File: sqlite_ai_assurance/local_model_scanner.py
import os
from pathlib import Path
import requests
from typing import List, Dict, Any


def discover_local_models() -> Dict[str, Any]:
    """
    Scans the laptop for all available local AI models across:
    1. Ollama Live API (http://localhost:11434/api/tags)
    2. LM Studio / OpenAI-Compatible Local Server (http://localhost:1234/v1/models)
    3. Custom Rust Inference Server (http://localhost:8080/health or /v1/models)
    4. On-Disk Model Caches (~/.ollama, ~/.cache/lm-studio, ~/.cache/huggingface, Desktop/Downloads *.gguf)
    """
    discovered_models: List[Dict[str, Any]] = []
    endpoints_status = {
        "ollama_live": False,
        "lm_studio_live": False,
        "rust_enclave_live": False
    }

    # 1. Check Live Ollama Daemon (Port 11434)
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=1.2)
        if resp.status_code == 200:
            endpoints_status["ollama_live"] = True
            data = resp.json()
            for m in data.get("models", []):
                size_gb = round(m.get("size", 0) / (1024 ** 3), 2)
                details = m.get("details", {})
                discovered_models.append({
                    "id": f"ollama::{m['name']}",
                    "name": m["name"],
                    "provider": "Ollama (Local Daemon)",
                    "endpoint": "http://localhost:11434/api/generate",
                    "size_gb": size_gb,
                    "param_size": details.get("parameter_size", "Local"),
                    "quantization": details.get("quantization_level", "GGUF"),
                    "status": "READY (LIVE)"
                })
    except Exception:
        pass

    # 2. Check Live LM Studio / Local OpenAI Server (Port 1234)
    try:
        resp = requests.get("http://localhost:1234/v1/models", timeout=1.0)
        if resp.status_code == 200:
            endpoints_status["lm_studio_live"] = True
            for m in resp.json().get("data", []):
                discovered_models.append({
                    "id": f"lmstudio::{m['id']}",
                    "name": m["id"],
                    "provider": "LM Studio (Port 1234)",
                    "endpoint": "http://localhost:1234/v1/chat/completions",
                    "size_gb": 0.0,
                    "param_size": "Local GGUF",
                    "quantization": "GGUF",
                    "status": "READY (LIVE)"
                })
    except Exception:
        pass

    # 3. Check Custom Rust Inference Server (Port 8080)
    try:
        resp = requests.get("http://localhost:8080/health", timeout=0.8)
        if resp.status_code == 200:
            endpoints_status["rust_enclave_live"] = True
            discovered_models.append({
                "id": "rust::local_enclave",
                "name": "Rust Native Inference Engine (Port 8080)",
                "provider": "Custom Rust Engine",
                "endpoint": "http://localhost:8080/completion",
                "size_gb": 0.0,
                "param_size": "Native Rust",
                "quantization": "Zeroized RAM",
                "status": "READY (LIVE)"
            })
    except Exception:
        pass

    # 4. Scan Laptop Filesystem for Offline / Cached Model Weights
    home = Path.home()
    seen_names = {m["name"] for m in discovered_models}

    # 4A. Check Ollama manifest folders if daemon wasn't running
    ollama_lib = home / ".ollama" / "models" / "manifests" / "registry.ollama.ai" / "library"
    if ollama_lib.exists():
        for model_dir in ollama_lib.iterdir():
            if model_dir.is_dir():
                for tag_file in model_dir.iterdir():
                    full_tag = f"{model_dir.name}:{tag_file.name}"
                    if full_tag not in seen_names:
                        discovered_models.append({
                            "id": f"ollama::{full_tag}",
                            "name": full_tag,
                            "provider": "Ollama (On Disk)",
                            "endpoint": "http://localhost:11434/api/generate",
                            "size_gb": 0.0,
                            "param_size": "Local",
                            "quantization": "GGUF",
                            "status": "ON DISK (Start `ollama serve`)"
                        })
                        seen_names.add(full_tag)

    # 4B. Check HuggingFace Hub cached models
    hf_hub = home / ".cache" / "huggingface" / "hub"
    if hf_hub.exists():
        for item in hf_hub.iterdir():
            if item.is_dir() and item.name.startswith("models--"):
                parts = item.name.split("--")
                # e.g., models--Qwen--Qwen2.5-0.5B-Instruct -> Qwen/Qwen2.5-0.5B-Instruct
                readable_name = "/".join(parts[1:]) if len(parts) >= 3 else item.name
                if readable_name not in seen_names:
                    # Calculate disk footprint
                    total_bytes = 0
                    has_safetensors = False
                    has_gguf = False
                    for root, _, files in os.walk(item):
                        for f in files:
                            if f.endswith(".safetensors"):
                                has_safetensors = True
                            if f.endswith(".gguf"):
                                has_gguf = True
                            fp = Path(root) / f
                            try:
                                total_bytes += fp.stat().st_size
                            except Exception:
                                pass
                    size_gb = round(total_bytes / (1024 ** 3), 2)
                    quant = "GGUF" if has_gguf else ("safetensors" if has_safetensors else "HF Weights")

                    discovered_models.append({
                        "id": f"hf::{readable_name}",
                        "name": readable_name,
                        "provider": "HuggingFace Hub Cache",
                        "endpoint": str(item),
                        "size_gb": size_gb,
                        "param_size": "Local HF Cache",
                        "quantization": quant,
                        "status": "ON DISK (Cached Weights)"
                    })
                    seen_names.add(readable_name)

    # 4C. Scan for raw .gguf files in common directories
    search_dirs = [
        home / ".cache" / "lm-studio" / "models",
        home / "Desktop",
        home / "Downloads",
    ]
    for base_dir in search_dirs:
        if not base_dir.exists():
            continue
        try:
            for root, dirs, files in os.walk(base_dir):
                depth = len(Path(root).relative_to(base_dir).parts)
                if depth > 3:
                    dirs[:] = []
                    continue
                for f in files:
                    if f.lower().endswith(".gguf") and f not in seen_names:
                        fpath = Path(root) / f
                        size_gb = round(fpath.stat().st_size / (1024 ** 3), 2)
                        discovered_models.append({
                            "id": f"gguf::{fpath}",
                            "name": f,
                            "provider": f"Local GGUF ({base_dir.name})",
                            "endpoint": str(fpath),
                            "size_gb": size_gb,
                            "param_size": "GGUF Weight",
                            "quantization": "GGUF",
                            "status": "ON DISK (Load in Rust/Ollama)"
                        })
                        seen_names.add(f)
        except Exception:
            continue

    # 4D. Always provide the built-in Deterministic Enclave Simulator as a baseline
    discovered_models.append({
        "id": "simulator::small_llm_enclave",
        "name": "Built-in Small LLM Enclave Simulator (Fallback)",
        "provider": "Internal Assurance Harness",
        "endpoint": "internal://simulator",
        "size_gb": 0.0,
        "param_size": "Deterministic",
        "quantization": "FP16-Sim",
        "status": "READY (BUILT-IN)"
    })

    return {
        "endpoints_status": endpoints_status,
        "models": discovered_models
    }


if __name__ == "__main__":
    import json
    print(json.dumps(discover_local_models(), indent=2))
