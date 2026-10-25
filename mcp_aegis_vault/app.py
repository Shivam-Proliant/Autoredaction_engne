"""Browser dashboard. Business actions go through the separate API and MCP service."""
import asyncio
import json
import urllib.error
import urllib.request

import pandas as pd
import streamlit as st
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

API_BASE = "http://127.0.0.1:8000"
MCP_URL = f"{API_BASE}/mcp"
CHECKOUT_DOMAIN = "checkout.currys.co.uk"
APPROVED_PAYLOAD = {
    "merchant": "Currys UK",
    "merchant_domain": CHECKOUT_DOMAIN,
    "items": [{"sku": "DEMO-SONY-STUDIO-HEADPHONES", "name": "Sony Studio Headphones", "quantity": 1, "unit_price_minor": 27900}],
    "total_minor": 27900,
    "currency": "GBP",
}
BAIT_PAYLOAD = {
    "merchant": "Currys UK",
    "merchant_domain": CHECKOUT_DOMAIN,
    "items": [{"sku": "DEMO-MACBOOK-PRO-M4", "name": "Apple MacBook Pro M4", "quantity": 1, "unit_price_minor": 250000}],
    "total_minor": 250000,
    "currency": "GBP",
}

st.set_page_config(page_title="Aegis Action Gateway", page_icon="🛡️", layout="wide")


def api_request(method: str, path: str, payload=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = st.session_state.get("aegis_session")
    if token:
        headers["X-Aegis-Session"] = token
    request = urllib.request.Request(API_BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail", str(exc))
        except Exception:
            detail = str(exc)
        raise RuntimeError(detail) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("Backend is offline. Start the local demo with run_demo.ps1.") from exc


def decode_tool_result(result):
    if getattr(result, "isError", False):
        raise RuntimeError("MCP tool call failed.")
    structured = getattr(result, "structuredContent", None) or getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    for item in getattr(result, "content", []):
        value = getattr(item, "text", None)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {"status": "ERROR", "reason": value}
    return {"status": "EMPTY_RESULT"}


async def _mcp_call(name, arguments):
    async with streamablehttp_client(MCP_URL, timeout=10, sse_read_timeout=15) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(name, arguments)
            return decode_tool_result(result)


def mcp_call(name, arguments):
    return asyncio.run(_mcp_call(name, arguments))


def show_json(label, value):
    st.markdown(f"**{label}**")
    st.json(value)


st.title("Aegis Action Gateway")
st.caption("Policy and human approval for agent actions · Real MCP over local HTTP · Simulated checkout only")
st.warning("Local prototype. Uses fake credentials and a no-network checkout simulator. Do not enter real credentials or expose this service to the internet.")

if not st.session_state.get("aegis_session"):
    try:
        first_use = api_request("GET", "/api/setup")["first_use"]
    except RuntimeError as exc:
        st.error(str(exc))
        st.stop()
    st.subheader("Unlock the local vault")
    with st.form("unlock_form"):
        password = st.text_input("Vault master password", type="password")
        confirm_password = st.text_input("Confirm master password", type="password") if first_use else None
        unlock = st.form_submit_button("Unlock Aegis")
    if unlock:
        try:
            unlock_request = {"password": password}
            if first_use:
                unlock_request["confirm_password"] = confirm_password
            result = api_request("POST", "/api/unlock", unlock_request)
            st.session_state.aegis_session = result["session_token"]
            st.session_state.totp_enrolled = result["totp_enrolled"]
            if result.get("enrollment_seed"):
                st.session_state.enrollment_seed = result["enrollment_seed"]
            st.rerun()
        except RuntimeError as exc:
            st.error(str(exc))
    st.stop()

try:
    service_state = api_request("GET", "/api/state")
except RuntimeError:
    st.session_state.clear()
    st.rerun()

with st.sidebar:
    st.subheader("Local services")
    st.success("Backend connected · MCP /mcp")
    st.caption("Bound to 127.0.0.1. The browser UI uses port 8502; backend and MCP use port 8000.")
    if st.button("Lock vault"):
        try:
            api_request("POST", "/api/lock")
        finally:
            st.session_state.clear()
            st.rerun()

if not service_state["totp_enrolled"]:
    st.subheader("Set up human approval")
    seed = st.session_state.get("enrollment_seed")
    if seed:
        st.info("Add this seed to your authenticator app. It is shown only until enrollment is confirmed.")
        st.code(seed)
        st.caption("In your authenticator, add an account named Aegis Local Demo using this Base32 key and time-based one-time passwords.")
    else:
        st.warning("Enrollment is not confirmed. Lock and unlock Aegis to resume setup.")
    with st.form("totp_enrollment"):
        enrollment_code = st.text_input("Current six-digit authenticator code", max_chars=6)
        confirm_enrollment = st.form_submit_button("Confirm authenticator setup")
    if confirm_enrollment:
        try:
            api_request("POST", "/api/enroll/confirm", {"code": enrollment_code})
            st.session_state.pop("enrollment_seed", None)
            st.success("Authenticator confirmed. The seed is now hidden.")
            st.rerun()
        except RuntimeError as exc:
            st.error(str(exc))
    st.stop()

st.success("Authenticator enrolled. Aegis will ask for a code only when you approve a transaction.")
credentials_tab, purchase_tab, audit_tab = st.tabs(["Credentials", "Shopping agent workflow", "Policy & audit"])

with credentials_tab:
    st.subheader("Credential handles available to agents")
    st.caption("Agents receive service metadata and handles only. Secret values are not exposed by the MCP tools.")
    if st.button("Add fake shopping records", key="seed_credentials"):
        try:
            result = api_request("POST", "/api/demo/seed")
            st.success(f"Added {result['added']} fake record(s).")
        except RuntimeError as exc:
            st.error(str(exc))
    if st.button("List handles through MCP", key="list_handles"):
        try:
            st.session_state.handle_result = mcp_call("mcp_vault_list_handles", {})
        except Exception as exc:
            st.error(f"MCP call failed: {exc}")
    if st.session_state.get("handle_result"):
        st.dataframe(pd.DataFrame(st.session_state.handle_result.get("credentials_metadata", [])), width="stretch", hide_index=True)
        st.caption(f"MCP result: secrets_exposed={st.session_state.handle_result.get('secrets_exposed')}")
    else:
        st.info("Seed the fake shopping records, then list handles through the real MCP endpoint.")

with purchase_tab:
    st.subheader("🛒 Buy Sony Studio Headphones · £279 · Currys UK")
    st.caption("The exact merchant, item, quantity, total, and currency are committed to the human-approved lease.")
    st.markdown("**Approved cart**")
    st.dataframe(pd.DataFrame(APPROVED_PAYLOAD["items"]), width="stretch", hide_index=True)
    st.markdown(f"Merchant: `{CHECKOUT_DOMAIN}` · Total: **£279.00 GBP**")

    if st.button("1. Ask agent to prepare this purchase", type="primary"):
        try:
            api_request("POST", "/api/demo/seed")
            handle_result = mcp_call("mcp_vault_list_handles", {})
            card = next((item for item in handle_result.get("credentials_metadata", []) if item.get("service") == "currys_business_card"), None)
            if not card:
                st.error("The fake Currys card handle was not found.")
            else:
                request_result = mcp_call("mcp_vault_request_lease", {
                    "cred_id": card["id"],
                    "target_domain": CHECKOUT_DOMAIN,
                    "expected_payload": APPROVED_PAYLOAD,
                })
                st.session_state.approval_request = request_result
                st.session_state.pop("lease_token", None)
                for key in ("tamper_result", "wrong_domain_result", "purchase_result", "replay_result"):
                    st.session_state.pop(key, None)
        except Exception as exc:
            st.error(f"Could not request an MCP lease: {exc}")

    request_result = st.session_state.get("approval_request")
    if request_result:
        show_json("2. Agent requested a lease through MCP", request_result)
        if request_result.get("status") == "STEP_UP_REQUIRED":
            st.info("3. Aegis paused the agent. Review the cart and approve with your authenticator.")
            with st.form("human_transaction_approval"):
                approval_code = st.text_input("Human approval code", max_chars=6)
                approve = st.form_submit_button("Approve £279 purchase")
            if approve:
                try:
                    api_request("POST", "/api/approve", {
                        "approval_request_id": request_result["approval_request_id"],
                        "totp_code": approval_code,
                    })
                    status_result = mcp_call("mcp_vault_approval_status", {"approval_request_id": request_result["approval_request_id"]})
                    if status_result.get("status") == "LEASE_GRANTED":
                        st.session_state.lease_token = status_result["lease_token"]
                        st.success("Human approval recorded. The MCP server issued a 60-second lease.")
                    else:
                        st.error(f"Approval status: {status_result.get('status')}")
                except Exception as exc:
                    st.error(f"Approval failed: {exc}")
        if st.session_state.get("lease_token"):
            st.markdown("**4. Lease ready** · One transaction · Exact merchant · 60-second expiry")
            if st.button("Try bait-and-switch cart on the same merchant"):
                st.session_state.tamper_result = mcp_call("mcp_vault_blind_execute", {
                    "lease_token": st.session_state.lease_token,
                    "target_url": f"https://{CHECKOUT_DOMAIN}/checkout",
                    "http_method": "POST",
                    "request_body": BAIT_PAYLOAD,
                })
            if st.session_state.get("tamper_result"):
                st.error("The MacBook substitution was blocked by the cart commitment.")
                show_json("Tamper attempt", st.session_state.tamper_result)
            if st.button("Try the approved checkout on a fake domain"):
                st.session_state.wrong_domain_result = mcp_call("mcp_vault_blind_execute", {
                    "lease_token": st.session_state.lease_token,
                    "target_url": "https://currys-deals.example.invalid/checkout",
                    "http_method": "POST",
                    "request_body": APPROVED_PAYLOAD,
                })
            if st.session_state.get("wrong_domain_result"):
                st.error("The unapproved hostname was blocked by domain pinning.")
                show_json("Wrong-domain attempt", st.session_state.wrong_domain_result)
            if not st.session_state.get("purchase_result") and st.button("5. Run the approved purchase in the local simulator"):
                st.session_state.purchase_result = mcp_call("mcp_vault_blind_execute", {
                    "lease_token": st.session_state.lease_token,
                    "target_url": f"https://{CHECKOUT_DOMAIN}/checkout",
                    "http_method": "POST",
                    "request_body": APPROVED_PAYLOAD,
                })
            if st.session_state.get("purchase_result"):
                result = st.session_state.purchase_result
                if result.get("status") == "SIMULATED_PURCHASE_COMPLETE":
                    st.success(f"Purchase simulated · order {result.get('simulated_order_id')} · no network request or credential injection")
                else:
                    st.error(result.get("reason", result.get("status")))
                show_json("Simulator result", result)
                if st.button("6. Replay the consumed lease"):
                    st.session_state.replay_result = mcp_call("mcp_vault_blind_execute", {
                        "lease_token": st.session_state.lease_token,
                        "target_url": f"https://{CHECKOUT_DOMAIN}/checkout",
                        "http_method": "POST",
                        "request_body": APPROVED_PAYLOAD,
                    })
                if st.session_state.get("replay_result"):
                    st.error("The replay was blocked; the lease has already been consumed.")
                    show_json("Replay result", st.session_state.replay_result)

with audit_tab:
    st.subheader("Recent policy decisions")
    if st.button("Refresh audit events") or not st.session_state.get("audit_rows"):
        try:
            st.session_state.audit_rows = api_request("GET", "/api/audit")["events"]
        except RuntimeError as exc:
            st.error(str(exc))
    audit_rows = st.session_state.get("audit_rows", [])
    if audit_rows:
        st.dataframe(pd.DataFrame(audit_rows), width="stretch", hide_index=True)
    else:
        st.info("No events yet. Run the purchase flow to see approvals and blocked attempts.")

with st.expander("MCP connection details"):
    st.code("http://127.0.0.1:8000/mcp")
    st.caption("Use this URL in MCP Inspector. The service is real MCP Streamable HTTP; the purchase tool is intentionally a local simulator.")
