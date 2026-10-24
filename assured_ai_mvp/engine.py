"""Deterministic, dependency-free redaction algorithms."""

from __future__ import annotations

import math
import ipaddress
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
GENERIC_LABELS = {
    "name", "full name", "first name", "last name", "email", "email id", "email address",
    "phone", "phone number", "mobile", "mobile number", "ip", "ip address", "api",
    "api key", "key", "token", "secret", "password", "address", "person", "customer",
    "credit card", "card number", "ssn", "national insurance number",
}
DETECTOR_LABELS = {
    "name": "Name",
    "address": "Address",
    "api_key": "API keys and tokens",
    "bank_account": "Bank account and sort code",
    "payment_card": "Credit and debit cards",
    "password": "Passwords and high-entropy secrets",
    "service_name": "Service names",
    "ethnicity": "Ethnicity",
    "region": "Regions and cities",
    "email": "Email addresses",
    "mobile": "Mobile numbers",
    "ip": "IP addresses",
    "amount": "Currency amounts",
    "identity": "National identifiers",
}
DEFAULT_DETECTORS = {key: True for key in DETECTOR_LABELS}
ENTITY_DETECTOR = {
    "PERSON_NAME": "name", "NAME": "name", "APPLICANT_NAME": "name", "CANDIDATE_NAME": "name",
    "ADDRESS": "address", "LOCATION": "address", "LOCATION_SITE": "address", "POSTAL_CODE": "address", "UK_POSTCODE": "address",
    "SECRET_API_KEY": "api_key", "API_KEY": "api_key", "ACCESS_TOKEN": "api_key", "BEARER_TOKEN": "api_key",
    "BANK_ACCOUNT": "bank_account", "ACCOUNT_NUMBER": "bank_account", "SORT_CODE": "bank_account",
    "PAYMENT_CARD": "payment_card", "CREDIT_CARD": "payment_card", "DEBIT_CARD": "payment_card",
    "PASSWORD": "password", "SECRET_CREDENTIAL": "password",
    "SERVICE_NAME": "service_name", "ETHNICITY": "ethnicity", "REGION": "region", "CITY": "region",
    "EMAIL": "email", "EMAIL_ADDRESS": "email", "MOBILE_NUMBER": "mobile", "PHONE_NUM": "mobile",
    "IPV4_ADDR": "ip", "IPV6_ADDR": "ip", "UK_NI_NUMBER": "identity", "US_SSN": "identity",
    "FINANCIAL_AMOUNT": "amount",
}
PATTERNS = [
    ("SECRET_API_KEY", "CRITICAL_SECRET", "API_KEY", "api_key", re.compile(r"(?<![A-Za-z0-9])(?:sk-(?:proj-|svcacct-|live_|test_|ant-)?[A-Za-z0-9_-]{12,}|pk_(?:live_|test_)?[A-Za-z0-9_-]{12,}|(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{30,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{16,})(?![A-Za-z0-9])", re.I)),
    ("SECRET_BEARER_TOKEN", "CRITICAL_SECRET", "BEARER_TOKEN", "api_key", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*", re.I)),
    ("EMAIL", "PII", "EMAIL", "email", re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\w-])")),
    ("UK_NI_NUMBER", "PII", "NI_NUMBER", "identity", re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.I)),
    ("IPV4_ADDR", "CONFIDENTIAL", "IPV4", "ip", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")),
    ("IPV6_ADDR", "CONFIDENTIAL", "IPV6", "ip", re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f:]{1,4}(?![\w:])")),
    ("MOBILE_NUMBER", "PII", "MOBILE_UK", "mobile", re.compile(r"(?<!\w)(?:\+44[\s().-]?7\d{3}|07\d{3})[\s().-]?\d{3}[\s().-]?\d{3}(?!\w)")),
    ("MOBILE_NUMBER", "PII", "MOBILE_NANP", "mobile", re.compile(r"(?<!\w)(?:\+?1[\s().-]?)?\(?[2-9]\d{2}\)?[\s().-]?[2-9]\d{2}[\s().-]?\d{4}(?!\w)")),
    ("MOBILE_NUMBER", "PII", "MOBILE_INTL", "mobile", re.compile(r"(?<!\w)\+\d{1,3}[\s().-]?(?:\d[\s().-]?){7,13}\d(?!\w)")),
    ("UK_POSTCODE", "PII", "POSTCODE", "address", re.compile(r"\b(?:GIR\s?0AA|(?:[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}))\b", re.I)),
    ("US_SSN", "PII", "SSN", "identity", re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?!\d)")),
    ("PAYMENT_CARD", "CRITICAL_SECRET", "CARD_NUMBER", "payment_card", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")),
    ("BANK_ACCOUNT", "CONFIDENTIAL", "ACCOUNT_NUMBER", "bank_account", re.compile(r"\b(?:bank\s+)?(?:account|acct)(?:\s+(?:number|no\.?))?\s*(?:is|[:=#])\s*([A-Z0-9][A-Z0-9-]{5,33})(?![A-Z0-9-])", re.I)),
    ("SORT_CODE", "CONFIDENTIAL", "SORT_CODE", "bank_account", re.compile(r"(?<!\d)\d{2}-\d{2}-\d{2}(?!\d)")),
    ("FINANCIAL_AMOUNT", "CONFIDENTIAL", "CURRENCY_AMOUNT", "amount", re.compile(r"(?<!\w)(?:£|\$|€|¥)\s?\d[\d,]*(?:\.\d{1,2})?(?!\w)")),
]
NAME_WORD = r"[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]+(?:[’'-][A-Z]?[a-zà-öø-ÿ]+)*"
NAME_CONTEXT_PATTERNS = [
    re.compile(rf"\b(?:my\s+name\s+is|the\s+name\s+is|under\s+the\s+name|name\s*[:=])\s+(?:(?:Mr|Mrs|Ms|Miss|Dr)\.?\s+)?(?P<person>{NAME_WORD}(?:\s+{NAME_WORD}){{0,2}})\b", re.I),
    re.compile(rf"\b(?:I\s+am|I'm|I’m|this\s+is|contact|account\s+holder)\s+(?:(?:Mr|Mrs|Ms|Miss|Dr)\.?\s+)?(?P<person>{NAME_WORD}(?:\s+{NAME_WORD}){{1,2}})\b", re.I),
    re.compile(rf"\b(?:customer|applicant|candidate|patient|employee)\s+(?:is|called|named)\s+(?P<person>{NAME_WORD}(?:\s+{NAME_WORD}){{0,2}})\b", re.I),
]
KEY_ASSIGNMENT = re.compile(r"\b(?:api(?:[_ -]?key)?|access[_ -]?token|client[_ -]?secret|(?:aws[_ -]?)?secret[_ -]?access[_ -]?key|password|passwd|secret|private[_ -]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_~+/-][A-Za-z0-9._~+/-]{6,}[A-Za-z0-9_~+/-]|[A-Za-z0-9_~+/-]{8,})", re.I)
ADDRESS_PATTERN = re.compile(r"\b\d{1,5}\s+[\w.'’#-]+(?:\s+[\w.'’#-]+){0,3}\s+(?:Road|Rd|Street|St|Avenue|Ave|Lane|Ln|Drive|Dr|Court|Close|Crescent|Way|Terrace|Place|Gardens?)\b(?:,\s*[A-Za-z][\w.'’-]*(?:\s+[A-Za-z][\w.'’-]*){0,2})?(?:,\s*(?:GIR\s?0AA|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}))?", re.I)
ACCOUNT_CONTEXT = re.compile(r"\b(?:bank\s+)?(?:account|acct)(?:\s+(?:number|no\.?))?\s*(?:is|[:=#])\s*(?P<value>[A-Z0-9][A-Z0-9-]{5,33})(?![A-Z0-9-])", re.I)
CARD_FRAGMENT = re.compile(r"\b(?:debit|credit|payment)\s+card\s+(?:ending(?:\s+in)?|last\s+(?:four|4)|number)\s*(?:is\s*)?(?P<value>\d{4,19}(?:[ -]\d{3,4}){0,3})\b", re.I)
PASSWORD_CONTEXT = re.compile(r"\b(?:password|passcode|passphrase)\s*(?:is|[:=])\s*['\"]?(?P<value>[^\s,;.'\"]{6,})", re.I)
SERVICE_CONTEXT = re.compile(r"\b(?:service\s+name|service|application|system)\s+(?:called|named|is|[:=])\s+(?P<value>[A-Z][A-Za-z0-9_-]*(?:\s+[A-Z][A-Za-z0-9_-]*){0,3})\b", re.I)
ETHNICITY_CONTEXT = re.compile(r"\b(?:ethnicity|ethnic\s+background|race)\s*(?:is|[:=])\s*(?P<value>Asian|Black|White|Mixed|Indian|Pakistani|Bangladeshi|Chinese|African|Caribbean|Arab|Latino|Latina|Latinx|Hispanic|Indigenous|Native\s+American|Pacific\s+Islander)\b", re.I)
REGION_NAMES = ["South West", "South East", "North West", "North East", "East Midlands", "West Midlands", "Yorkshire and the Humber", "East of England", "Northern Ireland", "London", "Scotland", "Wales", "Bristol", "Manchester", "Birmingham", "Liverpool", "Leeds", "Glasgow", "Edinburgh", "Cardiff", "Belfast", "Newcastle", "Nottingham", "Sheffield", "Oxford", "Cambridge"]
REGION_CONTEXT = re.compile(r"\b(?:region|county|city|town|based\s+in|located\s+in|from)\s+(?P<value>" + "|".join(re.escape(name) for name in sorted(REGION_NAMES, key=len, reverse=True)) + r")\b", re.I)
REGION_MENTIONS = re.compile(r"\b(?:" + "|".join(re.escape(name) for name in sorted(REGION_NAMES, key=len, reverse=True)) + r")\b", re.I)
ETHNICITY_LABEL = re.compile(r"\b(?:ethnicity|ethnic\s+background|race)\b", re.I)
SECRET_TOKEN = re.compile(r"(?<!\w)[A-Za-z0-9_!@#$%^&*+=~.-]{10,}(?!\w)")


class RedactionEngine:
    def __init__(self, protected_terms: list[dict]):
        self.terms = protected_terms

    def scan(self, text: str, enabled_detectors: dict[str, bool] | None = None) -> dict:
        started = time.perf_counter()
        candidates: list[dict] = []
        enabled = {**DEFAULT_DETECTORS, **(enabled_detectors or {})}

        # Structured patterns have highest priority.
        for entity, sensitivity, method, detector, pattern in PATTERNS:
            if not enabled.get(detector, True):
                continue
            for match in pattern.finditer(text):
                value = match.group(0)
                if entity == "IPV4_ADDR" and any(int(part) > 255 for part in value.split(".")):
                    continue
                if entity == "IPV6_ADDR":
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                if entity == "PAYMENT_CARD" and not self._passes_luhn(value):
                    continue
                if entity == "UK_NI_NUMBER" and value.replace(" ", "").upper()[:2] in {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}:
                    continue
                if entity == "BANK_ACCOUNT":
                    start, end = match.span(1)
                else:
                    start, end = match.span()
                candidates.append(self._candidate(start, end, entity, sensitivity, method, 1.0, False, detector))

        self._add_pattern_candidates(candidates, text, ADDRESS_PATTERN, "ADDRESS", "PII", "ADDRESS_CONTEXT", "address", enabled)
        self._add_pattern_candidates(candidates, text, ACCOUNT_CONTEXT, "BANK_ACCOUNT", "CONFIDENTIAL", "ACCOUNT_CONTEXT", "bank_account", enabled, group="value")
        self._add_pattern_candidates(candidates, text, CARD_FRAGMENT, "PAYMENT_CARD", "CRITICAL_SECRET", "CARD_FRAGMENT", "payment_card", enabled, group="value")
        self._add_pattern_candidates(candidates, text, PASSWORD_CONTEXT, "PASSWORD", "CRITICAL_SECRET", "PASSWORD_CONTEXT", "password", enabled, group="value")
        self._add_pattern_candidates(candidates, text, SERVICE_CONTEXT, "SERVICE_NAME", "CONFIDENTIAL", "SERVICE_CONTEXT", "service_name", enabled, group="value")
        self._add_pattern_candidates(candidates, text, ETHNICITY_CONTEXT, "ETHNICITY", "PII", "ETHNICITY_CONTEXT", "ethnicity", enabled, group="value")
        self._add_pattern_candidates(candidates, text, REGION_CONTEXT, "REGION", "PII", "REGION_CONTEXT", "region", enabled, group="value")

        if enabled.get("region", True):
            for match in REGION_MENTIONS.finditer(text):
                candidates.append(self._candidate(match.start(), match.end(), "REGION", "PII", "REGION_NAME", 0.98, False, "region"))

        # Credential labels provide useful context for unstructured API keys and secrets.
        for match in KEY_ASSIGNMENT.finditer(text):
            label_start = match.start()
            label = text[label_start:match.start(1)].casefold()
            detector = "password" if any(token in label for token in ("password", "passwd")) else "api_key"
            if enabled.get(detector, True):
                start, end = match.span(1)
                entity = "PASSWORD" if detector == "password" else "SECRET_CREDENTIAL"
                candidates.append(self._candidate(start, end, entity, "CRITICAL_SECRET", "KEY_LABEL", 1.0, False, detector))

        # Contextual name detection handles names that were never added to the term list.
        # Generic field labels such as "name" are never treated as personal names.
        for pattern in NAME_CONTEXT_PATTERNS if enabled.get("name", True) else []:
            for match in pattern.finditer(text):
                start, end = match.span("person")
                if not any(start < right and end > left for left, right in [(item["start"], item["end"]) for item in candidates]):
                    candidates.append(self._candidate(start, end, "PERSON_NAME", "PII", "NAME_CONTEXT", 0.95, False, "name"))

        words = list(WORD.finditer(text))
        occupied = [(item["start"], item["end"]) for item in candidates]
        for term in self.terms:
            target = term["value"]
            if target.strip().casefold() in GENERIC_LABELS:
                continue
            detector = ENTITY_DETECTOR.get(term["entity_type"].upper(), "service_name")
            if not enabled.get(detector, True):
                continue
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
                    candidate = self._candidate(start, end, term["entity_type"], term["sensitivity"], method, round(score, 3), review, detector)
                    candidates.append(candidate)
                    occupied.append((start, end))

        occupied = [(item["start"], item["end"]) for item in candidates]
        secret_prefixes = ("sk-", "pk_", "ghp_", "gho_", "akia", "eyj", "xoxb-", "bearer_")
        for match in SECRET_TOKEN.finditer(text):
            value = match.group(0)
            if any(match.start() < right and match.end() > left for left, right in occupied):
                continue
            if value.casefold().startswith(secret_prefixes):
                if enabled.get("api_key", True):
                    candidates.append(self._candidate(match.start(), match.end(), "SECRET_API_KEY", "CRITICAL_SECRET", "KEY_PREFIX", 1.0, False, "api_key"))
                continue
            if not enabled.get("password", True):
                continue
            classes = sum((any(c.isupper() for c in value), any(c.islower() for c in value), any(c.isdigit() for c in value), any(c in "_-!@#$%^&*+=~" for c in value)))
            if classes >= 3 and _entropy(value) >= 3.65:
                candidates.append(self._candidate(match.start(), match.end(), "SECRET_CREDENTIAL", "CRITICAL_SECRET", "HIGH_ENTROPY", 1.0, False, "password"))

        # Pick non-overlapping candidates, preferring structured patterns and longer matches.
        priority = {"ADDRESS_CONTEXT": 0, "API_KEY": 1, "BEARER_TOKEN": 1, "EMAIL": 1, "NI_NUMBER": 1, "IPV4": 1, "IPV6": 1, "MOBILE_UK": 1, "MOBILE_NANP": 1, "MOBILE_INTL": 1, "ACCOUNT_CONTEXT": 1, "CARD_FRAGMENT": 1, "PASSWORD_CONTEXT": 1}
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
    def _candidate(start: int, end: int, entity: str, sensitivity: str, method: str, score: float, review: bool, detector: str = "service_name") -> dict:
        return {
            "start": start, "end": end, "entity_type": entity, "sensitivity": sensitivity,
            "match_method": method, "similarity": score, "review_required": review, "detector": detector,
        }

    @staticmethod
    def _add_pattern_candidates(candidates: list[dict], text: str, pattern: re.Pattern, entity: str, sensitivity: str, method: str, detector: str, enabled: dict[str, bool], group: str | None = None) -> None:
        if not enabled.get(detector, True):
            return
        for match in pattern.finditer(text):
            start, end = match.span(group) if group else match.span()
            candidates.append(RedactionEngine._candidate(start, end, entity, sensitivity, method, 0.99, False, detector))

    @staticmethod
    def _passes_luhn(value: str) -> bool:
        digits = [int(char) for char in value if char.isdigit()]
        if not 13 <= len(digits) <= 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0
