"""Local prototype vault. Secrets are encrypted at rest; this is not production HSM code."""
import base64, hashlib, hmac, json, os, sqlite3, struct, time, uuid
from typing import Any
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

SHOPPING_DEMO_CREDENTIALS = (
    {
        "label": "Demo — Amazon UK purchasing passkey (fake)",
        "service": "amazon_uk_checkout",
        "credential_type": "WEBAUTHN_PASSKEY",
        "username": "buyer@example.invalid",
        "secret": "FAKE_WEBAUTHN_PRIVATE_KEY_NOT_VALID",
        "domains": ["amazon.co.uk", "payments.amazon.co.uk"],
        "stepup": True,
    },
    {
        "label": "Demo — single-merchant virtual Visa (fake)",
        "service": "currys_business_card",
        "credential_type": "PAYMENT_CARD_VCN",
        "username": "CARD_ENDING_0000",
        "secret": "PAN:0000-0000-0000-0000|EXP:01/99|CVV:000",
        "domains": ["currys.co.uk", "checkout.currys.co.uk"],
        "stepup": True,
    },
    {
        "label": "Demo — Shopify merchant API token (fake)",
        "service": "shopify_procurement",
        "credential_type": "OAUTH_BEARER_TOKEN",
        "username": "demo-store.myshopify.com",
        "secret": "shpat_demo_not_a_real_token",
        "domains": ["myshopify.com", "shopify.com"],
        "stepup": False,
    },
)

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def unb64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)

def totp(secret: str, at: int | None = None) -> tuple[str, int]:
    key = base64.b32decode(secret.strip().replace(" ", "").upper() + "=" * (-len(secret.strip().replace(" ", "")) % 8))
    now = int(time.time() if at is None else at)
    digest = hmac.new(key, struct.pack(">Q", now // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = (struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff) % 1_000_000
    return f"{value:06d}", 30 - now % 30

def canonical_payload(payload: dict[str, Any] | None) -> bytes:
    return json.dumps(payload or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

class Vault:
    def __init__(self, db_path: str, password: str):
        if len(password) < 12:
            raise ValueError("Use a master password with at least 12 characters.")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), salt TEXT NOT NULL, nonce TEXT NOT NULL, verifier TEXT NOT NULL, totp_nonce TEXT, totp_cipher TEXT, totp_enrolled INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS items (id TEXT PRIMARY KEY, label TEXT NOT NULL, service TEXT NOT NULL, username TEXT NOT NULL, domains TEXT NOT NULL, stepup INTEGER NOT NULL, wrap_nonce TEXT NOT NULL, wrapped_key TEXT NOT NULL, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL, credential_type TEXT NOT NULL DEFAULT 'API_BEARER_TOKEN');
        CREATE TABLE IF NOT EXISTS leases (token TEXT PRIMARY KEY, item_id TEXT NOT NULL, domain TEXT NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL, payload_sha256 TEXT NOT NULL DEFAULT '', FOREIGN KEY(item_id) REFERENCES items(id));
        CREATE TABLE IF NOT EXISTS approval_requests (id TEXT PRIMARY KEY, item_id TEXT NOT NULL, domain TEXT NOT NULL, payload_json TEXT NOT NULL, amount_minor INTEGER NOT NULL, currency TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL, lease_token TEXT, FOREIGN KEY(item_id) REFERENCES items(id));
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT DEFAULT CURRENT_TIMESTAMP, event TEXT, item_id TEXT, domain TEXT, outcome TEXT);
        """)
        meta_columns = {r[1] for r in self.conn.execute("PRAGMA table_info(meta)")}
        if "totp_enrolled" not in meta_columns:
            self.conn.execute("ALTER TABLE meta ADD COLUMN totp_enrolled INTEGER NOT NULL DEFAULT 0")
            self.conn.commit()
        item_columns = {r["name"] for r in self.conn.execute("PRAGMA table_info(items)")}
        self._legacy_item_ids = []
        if "credential_type" not in item_columns:
            self._legacy_item_ids = [r[0] for r in self.conn.execute("SELECT id FROM items")]
            self.conn.execute("ALTER TABLE items ADD COLUMN credential_type TEXT NOT NULL DEFAULT 'API_BEARER_TOKEN'")
            self.conn.commit()
        lease_columns = {r["name"] for r in self.conn.execute("PRAGMA table_info(leases)")}
        if "payload_sha256" not in lease_columns:
            self.conn.execute("ALTER TABLE leases ADD COLUMN payload_sha256 TEXT NOT NULL DEFAULT ''")
            self.conn.commit()
        row = self.conn.execute("SELECT * FROM meta WHERE id=1").fetchone()
        if not row:
            salt = os.urandom(16)
            self.key = hash_secret_raw(password.encode(), salt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)
            nonce = os.urandom(12)
            verifier = AESGCM(self.key).encrypt(nonce, b"AEGIS-LOCAL-VAULT-v1", b"vault-verifier")
            seed = base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")
            tn = os.urandom(12)
            tc = AESGCM(self.key).encrypt(tn, seed.encode(), b"totp-seed-v1")
            self.conn.execute("INSERT INTO meta (id,salt,nonce,verifier,totp_nonce,totp_cipher,totp_enrolled) VALUES(1,?,?,?,?,?,0)", (b64(salt),b64(nonce),b64(verifier),b64(tn),b64(tc)))
            self.conn.commit()
            self.totp_seed = seed
            self.totp_enrolled = False
        else:
            self.key = hash_secret_raw(password.encode(), unb64(row["salt"]), time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, type=Type.ID)
            try:
                AESGCM(self.key).decrypt(unb64(row["nonce"]), unb64(row["verifier"]), b"vault-verifier")
                self.totp_seed = AESGCM(self.key).decrypt(unb64(row["totp_nonce"]),unb64(row["totp_cipher"]),b"totp-seed-v1").decode()
                self.totp_enrolled = bool(row["totp_enrolled"])
            except Exception as exc:
                raise ValueError("Could not unlock vault; check the master password.") from exc
        self._migrate_legacy_item_aad()

    def _migrate_legacy_item_aad(self):
        """Re-encrypt rows created before credential_type was included in AEAD AAD."""
        for item_id in self._legacy_item_ids:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            old_aad = json.dumps(["aegis-v1", row["id"], row["service"], json.loads(row["domains"]), int(row["stepup"])], separators=(",", ":")).encode()
            dek = AESGCM(self.key).decrypt(unb64(row["wrap_nonce"]), unb64(row["wrapped_key"]), old_aad)
            secret = ChaCha20Poly1305(dek).decrypt(unb64(row["nonce"]), unb64(row["ciphertext"]), old_aad)
            new_aad = self.aad(row["id"], row["service"], row["credential_type"], row["domains"], row["stepup"])
            wrap_nonce, nonce = os.urandom(12), os.urandom(12)
            wrapped = AESGCM(self.key).encrypt(wrap_nonce, dek, new_aad)
            ciphertext = ChaCha20Poly1305(dek).encrypt(nonce, secret, new_aad)
            self.conn.execute("UPDATE items SET wrap_nonce=?,wrapped_key=?,nonce=?,ciphertext=? WHERE id=?", (b64(wrap_nonce),b64(wrapped),b64(nonce),b64(ciphertext),item_id))
        if self._legacy_item_ids:
            self.conn.commit()
            self._legacy_item_ids = []

    @staticmethod
    def aad(item_id: str, service: str, credential_type: str, domains: str, stepup: int) -> bytes:
        return json.dumps(["aegis-v1", item_id, service, credential_type, json.loads(domains), int(stepup)], separators=(",", ":")).encode()

    def add_item(self, label: str, service: str, username: str, secret: str, domains: list[str], stepup: bool, credential_type: str = "API_BEARER_TOKEN") -> str:
        clean = sorted({d.strip().lower().rstrip(".") for d in domains if d.strip()})
        if not label.strip() or not service.strip() or not secret or not clean or any("/" in d or ":" in d or " " in d for d in clean):
            raise ValueError("Enter a label, service, secret, and valid pinned hostnames.")
        item_id, policy = "cred_" + uuid.uuid4().hex, json.dumps(clean, separators=(",", ":"))
        flag, aad = int(stepup), self.aad(item_id, service.strip(), credential_type, policy, int(stepup))
        dek, nonce, wrap_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
        cipher = ChaCha20Poly1305(dek).encrypt(nonce, secret.encode(), aad)
        wrapped = AESGCM(self.key).encrypt(wrap_nonce, dek, aad)
        self.conn.execute("INSERT INTO items (id,label,service,username,domains,stepup,wrap_nonce,wrapped_key,nonce,ciphertext,credential_type) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (item_id,label.strip(),service.strip(),username.strip(),policy,flag,b64(wrap_nonce),b64(wrapped),b64(nonce),b64(cipher),credential_type))
        self.conn.commit()
        return item_id

    def items(self):
        return [dict(r) for r in self.conn.execute("SELECT id,label,service,credential_type,username,domains,stepup FROM items ORDER BY label")]

    def seed_shopping_demo_credentials(self) -> int:
        """Add fake, nonfunctional shopping records once; never seeds user accounts automatically."""
        existing_services = {r["service"] for r in self.items()}
        added = 0
        for demo in SHOPPING_DEMO_CREDENTIALS:
            if demo["service"] not in existing_services:
                self.add_item(demo["label"], demo["service"], demo["username"], demo["secret"], demo["domains"], demo["stepup"], demo["credential_type"])
                added += 1
        return added

    def confirm_totp_enrollment(self, code: str) -> bool:
        if not hmac.compare_digest(totp(self.totp_seed)[0], code.strip()):
            self.audit("TOTP_ENROLLMENT", None, None, "invalid_code")
            return False
        self.conn.execute("UPDATE meta SET totp_enrolled=1 WHERE id=1")
        self.conn.commit()
        self.totp_enrolled = True
        self.audit("TOTP_ENROLLMENT", None, None, "confirmed")
        return True

    def create_approval_request(self, item_id: str, domain: str, expected_payload: dict[str, Any]) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not row:
            return {"status": "DENIED", "reason": "Unknown credential handle."}
        d = domain.strip().lower().rstrip(".")
        allowed = json.loads(row["domains"])
        if d not in allowed:
            self.audit("LEASE_REQUEST", item_id, d, "domain_denied")
            return {"status": "DENIED_DOMAIN", "reason": "Requested hostname is not on the item's allowlist."}
        if not isinstance(expected_payload, dict):
            return {"status": "DENIED", "reason": "Expected transaction payload must be an object."}
        try:
            payload = json.loads(canonical_payload(expected_payload))
            amount_minor = int(payload.get("total_minor", 0))
            currency = str(payload.get("currency", "GBP"))
            line_items = payload.get("items")
            if payload.get("merchant_domain") != d or not isinstance(line_items, list) or not line_items:
                return {"status": "DENIED", "reason": "Approved payload must name the exact pinned merchant and include line items."}
            calculated_total = 0
            for line in line_items:
                quantity = int(line["quantity"])
                unit_price_minor = int(line["unit_price_minor"])
                if quantity < 1 or unit_price_minor < 0 or not line.get("sku") or not line.get("name"):
                    return {"status": "DENIED", "reason": "Each cart line needs an item, SKU, positive quantity, and non-negative price."}
                calculated_total += quantity * unit_price_minor
        except (ValueError, TypeError, json.JSONDecodeError):
            return {"status": "DENIED", "reason": "Transaction payload is invalid."}
        except (KeyError, AttributeError):
            return {"status": "DENIED", "reason": "Transaction cart line is incomplete."}
        if amount_minor < 0 or currency != "GBP" or amount_minor != calculated_total:
            return {"status": "DENIED", "reason": "Demo policy requires an accurate, non-negative GBP total."}
        request_id = "approval_" + uuid.uuid4().hex
        now = time.time()
        self.conn.execute(
            "INSERT INTO approval_requests (id,item_id,domain,payload_json,amount_minor,currency,created,expires,status) VALUES(?,?,?,?,?,?,?,?,?)",
            (request_id, item_id, d, json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False), amount_minor, currency, now, now + 300, "PENDING"),
        )
        self.conn.commit()
        self.audit("APPROVAL_REQUESTED", item_id, d, "pending_human_step_up")
        return {"status": "STEP_UP_REQUIRED", "approval_request_id": request_id, "expires_in_seconds": 300, "amount_minor": amount_minor, "currency": currency}

    def approve_request(self, request_id: str, code: str) -> dict[str, Any]:
        request = self.conn.execute("SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone()
        if not request:
            return {"status": "DENIED", "reason": "Unknown approval request."}
        if request["status"] == "APPROVED" and request["lease_token"]:
            return {"status": "LEASE_GRANTED", "approval_request_id": request_id}
        if request["status"] != "PENDING" or time.time() > request["expires"]:
            self.conn.execute("UPDATE approval_requests SET status='EXPIRED' WHERE id=? AND status='PENDING'", (request_id,))
            self.conn.commit()
            self.audit("HUMAN_APPROVAL", request["item_id"], request["domain"], "expired_or_closed")
            return {"status": "BLOCKED_EXPIRED_APPROVAL", "reason": "Approval request expired or is no longer pending."}
        if not self.totp_enrolled:
            return {"status": "TOTP_ENROLLMENT_REQUIRED", "reason": "Enroll an authenticator before approving transactions."}
        result = self.grant_lease(
            request["item_id"], request["domain"], code,
            amount_gbp=request["amount_minor"] / 100,
            approval_threshold_gbp=100,
            expected_payload=json.loads(request["payload_json"]),
        )
        if result.get("status") != "LEASE_GRANTED":
            self.audit("HUMAN_APPROVAL", request["item_id"], request["domain"], "totp_rejected")
            return result
        self.conn.execute("UPDATE approval_requests SET status='APPROVED',lease_token=? WHERE id=?", (result["lease_token"], request_id))
        self.conn.commit()
        self.audit("HUMAN_APPROVAL", request["item_id"], request["domain"], "approved")
        return {"status": "LEASE_GRANTED", "approval_request_id": request_id, "expires_in_seconds": result["expires_in_seconds"]}

    def approval_status(self, request_id: str) -> dict[str, Any]:
        request = self.conn.execute("SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone()
        if not request:
            return {"status": "DENIED", "reason": "Unknown approval request."}
        if request["status"] == "PENDING" and time.time() > request["expires"]:
            self.conn.execute("UPDATE approval_requests SET status='EXPIRED' WHERE id=?", (request_id,))
            self.conn.commit()
            return {"status": "EXPIRED", "expires_in_seconds": 0}
        if request["status"] == "APPROVED":
            return {"status": "LEASE_GRANTED", "lease_token": request["lease_token"], "expires_in_seconds": 60}
        return {"status": request["status"], "expires_in_seconds": max(0, int(request["expires"] - time.time()))}

    def grant_lease(self, item_id: str, domain: str, code: str = "", amount_gbp: float = 0, approval_threshold_gbp: float | None = None, expected_payload: dict[str, Any] | None = None) -> dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not row: return {"status":"DENIED", "reason":"Unknown credential handle."}
        d = domain.strip().lower().rstrip(".")
        try:
            policy = json.loads(row["domains"])
            aad = self.aad(row["id"],row["service"],row["credential_type"],row["domains"],row["stepup"])
            dek = AESGCM(self.key).decrypt(unb64(row["wrap_nonce"]),unb64(row["wrapped_key"]),aad)
            ChaCha20Poly1305(dek).decrypt(unb64(row["nonce"]),unb64(row["ciphertext"]),aad)
        except Exception:
            self.audit("AAD_TAMPER",item_id,d,"blocked")
            return {"status":"CRYPTO_TAMPER_LOCKDOWN", "reason":"Authenticated policy/ciphertext check failed."}
        if d not in policy:
            self.audit("LEASE_REQUEST",item_id,d,"domain_denied")
            return {"status":"DENIED_DOMAIN", "reason":"Requested hostname is not on the item's allowlist."}
        stepup_required = bool(row["stepup"]) or (approval_threshold_gbp is not None and amount_gbp > approval_threshold_gbp)
        if stepup_required and (not self.totp_enrolled or not hmac.compare_digest(totp(self.totp_seed)[0],code.strip())):
            self.audit("STEP_UP_REQUIRED",item_id,d,"awaiting_human_totp")
            return {"status":"STEP_UP_REQUIRED", "reason":"Enter the current authenticator code."}
        canonical_payload_bytes = canonical_payload(expected_payload)
        payload_hash = hashlib.sha256(canonical_payload_bytes).hexdigest()
        token = "mcp_lease_" + uuid.uuid4().hex
        self.conn.execute("INSERT INTO leases (token,item_id,domain,expires,status,payload_sha256) VALUES(?,?,?,?,?,?)",(token,item_id,d,time.time()+60,"ACTIVE",payload_hash))
        self.conn.commit(); self.audit("LEASE_MINTED",item_id,d,"granted")
        return {"status":"LEASE_GRANTED","lease_token":token,"expires_in_seconds":60,"committed_payload_sha256":payload_hash}

    def execute_mock(self, token: str, url: str, method: str = "GET", request_body: dict[str, Any] | None = None) -> dict[str, Any]:
        from urllib.parse import urlsplit
        lease = self.conn.execute("SELECT * FROM leases WHERE token=?",(token,)).fetchone()
        try:
            parsed = urlsplit(url)
            parsed_port = parsed.port
        except ValueError:
            self.audit("MOCK_EXECUTION", None, None, "invalid_url")
            return {"status":"BLOCKED","reason":"Malformed checkout URL."}
        if not lease:
            self.audit("MOCK_EXECUTION", None, parsed.hostname, "unknown_lease")
            return {"status":"BLOCKED","reason":"Unknown lease."}
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or host != lease["domain"] or parsed.username or parsed.password or parsed_port not in (None, 443):
            self.audit("MOCK_EXECUTION", lease["item_id"], host, "domain_or_url_blocked")
            return {"status":"BLOCKED","reason":"Only HTTPS to the exact pinned hostname is permitted."}
        actual_hash = hashlib.sha256(canonical_payload(request_body)).hexdigest()
        if lease["payload_sha256"] and actual_hash != lease["payload_sha256"]:
            self.audit("PAYLOAD_TAMPER_BLOCKED", lease["item_id"], host, "payload_hash_mismatch")
            return {"status":"BLOCKED_PAYLOAD_HASH_MISMATCH","reason":f"Approved transaction SHA-256 ({lease['payload_sha256'][:10]}...) does not match attempted payload ({actual_hash[:10]}...)."}
        if lease["status"] != "ACTIVE" or time.time() > lease["expires"]:
            self.audit("MOCK_EXECUTION", lease["item_id"], host, "replay_or_expired")
            return {"status":"BLOCKED_REPLAY_OR_EXPIRED","reason":"Lease is consumed or expired."}
        self.conn.execute("UPDATE leases SET status='CONSUMED' WHERE token=? AND status='ACTIVE'",(token,)); self.conn.commit()
        self.audit("MOCK_EXECUTION",lease["item_id"],host,"simulated_no_network")
        order_id = "sim_order_" + uuid.uuid4().hex[:12]
        return {"status":"SIMULATED_PURCHASE_COMPLETE","simulated_order_id":order_id,"method":method.upper(),"host":host,"credential_sent":False,"network_request_made":False,"message":"Local simulator completed the approved purchase; no outbound request was made and no credential was injected."}

    def audit(self,event,item_id,domain,outcome):
        self.conn.execute("INSERT INTO audit(event,item_id,domain,outcome) VALUES(?,?,?,?)",(event,item_id,domain,outcome)); self.conn.commit()

    def audit_rows(self): return [dict(r) for r in self.conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")]
