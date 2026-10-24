"""Deterministic, dependency-free redaction algorithms."""

from __future__ import annotations

import math
import re
import time


def _soundex(value: str) -> str:
    letters = re.sub(r"[^A-Za-z]", "", value).upper()
    if not letters:
        return "0000"
    codes = {**dict.fromkeys("BFPV", "1"), **dict.fromkeys("CGJKQSXZ", "2"),
             **dict.fromkeys("DT", "3"), "L": "4", **dict.fromkeys("MN", "5"), "R": "6"}
    out = [letters[0]]
    previous = codes.get(letters[0], "0")
    for char in letters[1:]:
        code = codes.get(char, "0")
        if code != "0" and code != previous:
            out.append(code)
        previous = code
    return ("".join(out) + "000")[:4]


def _similarity(left: str, right: str) -> float:
    """Normalized unrestricted Damerau–Levenshtein similarity."""
    a, b = left.casefold(), right.casefold()
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    n, m = len(a), len(b)
    inf = n + m
    matrix = [[0] * (m + 2) for _ in range(n + 2)]
    matrix[0][0] = inf
    for i in range(n + 1):
        matrix[i + 1][0] = inf
        matrix[i + 1][1] = i
    for j in range(m + 1):
        matrix[0][j + 1] = inf
        matrix[1][j + 1] = j
    last_seen: dict[str, int] = {}
    for i in range(1, n + 1):
        last_match_col = 0
        for j in range(1, m + 1):
            i1 = last_seen.get(b[j - 1], 0)
            j1 = last_match_col
            cost = 1
            if a[i - 1] == b[j - 1]:
                cost = 0
                last_match_col = j
            matrix[i + 1][j + 1] = min(
                matrix[i][j] + cost,
                matrix[i + 1][j] + 1,
                matrix[i][j + 1] + 1,
                matrix[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        last_seen[a[i - 1]] = i
    distance = matrix[n + 1][m + 1]
    return 1.0 - distance / max(n, m)


def _entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


WORD = re.compile(r"[A-Za-z0-9]+(?:[_'’./:@+-][A-Za-z0-9]+)*")
PATTERNS = [
    ("SECRET_API_KEY", "CRITICAL_SECRET", "API_KEY", re.compile(r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,})(?![A-Za-z0-9])", re.I)),
    ("SECRET_BEARER_TOKEN", "CRITICAL_SECRET", "BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*", re.I)),
    ("EMAIL", "PII", "EMAIL", re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\w.-])")),
    ("UK_NI_NUMBER", "PII", "NI_NUMBER", re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.I)),
    ("IPV4_ADDR", "CONFIDENTIAL", "IPV4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("PHONE_NUM", "PII", "PHONE", re.compile(r"(?<!\w)(?:\+44\s?7\d{3}|07\d{3})\s?\d{3}\s?\d{3}(?!\w)")),
]
SECRET_TOKEN = re.compile(r"(?<!\w)[A-Za-z0-9_!@#$%^&*+=~.-]{10,}(?!\w)")


class RedactionEngine:
    def __init__(self, protected_terms: list[dict]):
        self.terms = protected_terms

    def scan(self, text: str) -> dict:
        started = time.perf_counter()
        candidates: list[dict] = []

        # Structured patterns have highest priority.
        for entity, sensitivity, method, pattern in PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if entity == "IPV4_ADDR" and any(int(part) > 255 for part in value.split(".")):
                    continue
                if entity == "UK_NI_NUMBER" and value.replace(" ", "").upper()[:2] in {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}:
                    continue
                candidates.append(self._candidate(match.start(), match.end(), entity, sensitivity, method, 1.0, False))

        words = list(WORD.finditer(text))
        occupied = [(item["start"], item["end"]) for item in candidates]
        for term in self.terms:
            target = term["value"]
            normalized_target = re.sub(r"[^a-z0-9]", "", target.casefold())
            target_words = WORD.findall(target)
            if not normalized_target or not target_words:
                continue
            for i in range(len(words)):
                # Multiword terms allow ±1 token for punctuation/spacing variants.
                for count in range(max(1, len(target_words) - 1), len(target_words) + 2):
                    j = i + count - 1
                    if j >= len(words):
                        continue
                    start, end = words[i].start(), words[j].end()
                    if any(start < right and end > left for left, right in occupied):
                        continue
                    candidate_text = text[start:end]
                    normalized_candidate = re.sub(r"[^a-z0-9]", "", candidate_text.casefold())
                    if not normalized_candidate or abs(len(normalized_candidate) - len(normalized_target)) > max(3, len(normalized_target) // 3):
                        continue
                    score = _similarity(normalized_candidate, normalized_target)
                    phonetic = (
                        len(normalized_candidate) >= 3
                        and abs(len(normalized_candidate) - len(normalized_target)) <= 2
                        and _soundex(normalized_candidate) == _soundex(normalized_target)
                    )
                    if score == 1.0:
                        method, review = "EXACT", False
                    elif phonetic and score < 0.84:
                        score, method, review = 0.84, "PHONETIC", False
                    elif score >= 0.78:
                        method, review = "FUZZY_DAMERAU_LEVENSHTEIN", False
                    elif score >= 0.68:
                        method, review = "FUZZY_REVIEW", True
                    else:
                        continue
                    candidate = self._candidate(start, end, term["entity_type"], term["sensitivity"], method, round(score, 3), review)
                    candidates.append(candidate)
                    occupied.append((start, end))

        occupied = [(item["start"], item["end"]) for item in candidates]
        secret_prefixes = ("sk-", "pk_", "ghp_", "gho_", "akia", "eyj", "xoxb-", "bearer_")
        for match in SECRET_TOKEN.finditer(text):
            value = match.group(0)
            if any(match.start() < right and match.end() > left for left, right in occupied):
                continue
            classes = sum((any(c.isupper() for c in value), any(c.islower() for c in value), any(c.isdigit() for c in value), any(c in "_-!@#$%^&*+=~" for c in value)))
            if value.casefold().startswith(secret_prefixes) or (classes >= 3 and _entropy(value) >= 3.65):
                candidates.append(self._candidate(match.start(), match.end(), "SECRET_CREDENTIAL", "CRITICAL_SECRET", "HIGH_ENTROPY", 1.0, False))

        # Pick non-overlapping candidates, preferring structured patterns and longer matches.
        priority = {"API_KEY": 0, "BEARER_TOKEN": 0, "EMAIL": 0, "NI_NUMBER": 0, "IPV4": 0, "PHONE": 0}
        candidates.sort(key=lambda item: (priority.get(item["match_method"], 1), item["start"], -(item["end"] - item["start"])))
        selected: list[dict] = []
        for item in candidates:
            if any(item["start"] < found["end"] and item["end"] > found["start"] for found in selected):
                continue
            selected.append(item)
        selected.sort(key=lambda item: item["start"])
        for index, item in enumerate(selected, 1):
            item["placeholder"] = "{{" + re.sub(r"[^A-Z0-9]+", "_", item["entity_type"].upper()).strip("_") + f"_{index:02d}" + "}}"
            item["raw_value"] = text[item["start"]:item["end"]]

        pieces, cursor = [], 0
        for item in selected:
            pieces.append(text[cursor:item["start"]])
            pieces.append(item["placeholder"])
            cursor = item["end"]
        pieces.append(text[cursor:])
        return {
            "redacted_text": "".join(pieces),
            "matches": selected,
            "review_count": sum(item["review_required"] for item in selected),
            "processing_ms": round((time.perf_counter() - started) * 1000, 3),
        }

    @staticmethod
    def _candidate(start: int, end: int, entity: str, sensitivity: str, method: str, score: float, review: bool) -> dict:
        return {
            "start": start, "end": end, "entity_type": entity, "sensitivity": sensitivity,
            "match_method": method, "similarity": score, "review_required": review,
        }
