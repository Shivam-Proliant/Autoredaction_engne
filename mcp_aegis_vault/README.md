# Aegis Action Gateway

Local browser demo of a policy and human-approval gateway for agent actions. It uses the official MCP Python SDK over Streamable HTTP, a FastAPI backend, and a local SQLite vault. The Currys checkout is simulated: no live merchant is contacted, no payment is made, and no credential is injected.

## Start the demo on Windows

1. Install Python 3.14 and allow package installation once:

   ```powershell
   py -3.14 -m pip install --target .runtime_packages -r requirements.txt
   ```

2. Run `run_demo.ps1`. It starts the backend/MCP endpoint on `127.0.0.1:8000`, opens the browser UI on `127.0.0.1:8502`, and opens Chrome using the system browser handler.

3. Create or unlock the local vault. On first use, add the displayed Base32 seed to an authenticator and confirm enrollment. The seed is hidden after confirmation; Aegis never displays a live TOTP code.

For MCP Inspector, connect to `http://127.0.0.1:8000/mcp`. The server tools list handles, request approval, check approval status, and run the local simulator.

## Demo flow

The browser UI acts as an MCP client. It requests approval for a £279 Currys headphones cart, waits for the user to approve with TOTP, then receives a 60-second lease from the MCP server. A MacBook cart substitution, wrong hostname, and lease replay are blocked and audited. The approved payload runs through the local simulator and returns a fake order ID.

## Limits

This is a single-user local prototype, not a production password manager or hosted service. The audit log is not tamper-proof, Python cannot guarantee memory zeroization, and the implementation has not received a security review. Keep both services on localhost and use only the provided fake records.
