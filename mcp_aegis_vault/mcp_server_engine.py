"""In-process JSON-RPC tool router for the Aegis local prototype."""
import hashlib
import json
from urllib.parse import urlsplit

class AegisMCPServer:
    def __init__(self, vault): self.vault = vault

    def handle_jsonrpc(self, request):
        rid = request.get("id")
        if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32600,"message":"Invalid JSON-RPC request"}}
        method, params = request["method"], request.get("params") or {}
        if method == "tools/list":
            return {"jsonrpc":"2.0","id":rid,"result":{"tools":[
                {"name":"mcp_vault_list_handles","description":"List credential metadata only.","inputSchema":{"type":"object","properties":{}}},
                {"name":"mcp_vault_request_lease","description":"Request a short lived, domain pinned lease; high value demo purchases can require step-up approval.","inputSchema":{"type":"object","properties":{"cred_id":{"type":"string"},"target_domain":{"type":"string"},"totp_code":{"type":"string"},"amount_gbp":{"type":"number"},"approval_threshold_gbp":{"type":"number"},"expected_payload":{"type":"object"}},"required":["cred_id","target_domain"]}},
                {"name":"mcp_vault_blind_execute","description":"Consume a lease in mock mode; no network request is made. The request body must match the lease payload commitment.","inputSchema":{"type":"object","properties":{"lease_token":{"type":"string"},"target_url":{"type":"string"},"http_method":{"type":"string"},"request_body":{"type":"object"}},"required":["lease_token","target_url"]}}]}}
        if method != "tools/call": return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":"Method not found"}}
        name, args = params.get("name"), params.get("arguments") or {}
        if name == "mcp_vault_list_handles": result = {"credentials_metadata":self.vault.items(),"secrets_exposed":False}
        elif name == "mcp_vault_request_lease": result = self.vault.grant_lease(args.get("cred_id",""),args.get("target_domain",""),args.get("totp_code",""),args.get("amount_gbp",0),args.get("approval_threshold_gbp"),args.get("expected_payload",{}))
        elif name == "mcp_vault_blind_execute": result = self.tool_blind_execute(args.get("lease_token",""),args.get("target_url",""),args.get("http_method","GET"),args.get("request_body",{}))
        else: return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":"Unknown tool"}}
        return {"jsonrpc":"2.0","id":rid,"result":result}

    def tool_blind_execute(self, lease_token, target_url, http_method="GET", request_body=None):
        lease = self.vault.conn.execute("SELECT * FROM leases WHERE token=?", (lease_token,)).fetchone()
        actual_hash = hashlib.sha256(json.dumps(request_body or {}, sort_keys=True).encode("utf-8")).hexdigest()
        if lease and lease["payload_sha256"] and actual_hash != lease["payload_sha256"]:
            self.vault.audit("PAYLOAD_TAMPER_BLOCKED", lease["item_id"], lease["domain"], "payload_hash_mismatch")
            expected = lease["payload_sha256"]
            return {
                "status": "BLOCKED_PAYLOAD_HASH_MISMATCH",
                "reason": f"Transaction Integrity Violation! Human approved payload SHA-256 ({expected[:10]}...), but agent attempted to execute modified cart/payload ({actual_hash[:10]}...).",
            }
        return self.vault.execute_mock(lease_token, target_url, http_method)
