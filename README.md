# TrustAuth

TrustAuth is a hardware-backed authentication system that combines:
- Password verification (something you know)
- Device proof via TPM-compatible key challenge signing (something you have)

## Features
- User registration with device enrollment
- Challenge-response login
- JWT-based authenticated sessions
- Device listing and revocation
- Authentication audit logs
- Minimal dashboard for API checks

## Project Structure
```text
api/
client/
database/
tpm_manager/
dashboard/
tests/
```

## Quick Start (Windows PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set a secure value in `.env` for `JWT_SECRET`.
Ensure MongoDB is running locally on `mongodb://localhost:27017` (or update `.env`).

## Run API
```powershell
python -m api.server
```

- **Web dashboard (full UI):** open [http://localhost:8000/](http://localhost:8000/) in your browser after the API is running. The UI supports register, login (challenge + Web Crypto signature), device list, revoke, sessions, and logout.
- **Swagger:** [http://localhost:8000/docs](http://localhost:8000/docs)

Use the same machine or keep the default API base URL in the header; for a remote API, change **API base** in the dashboard.

### Browser + TPM (recommended for UI + real TPM)

Web pages cannot access the platform TPM directly. Run a **local TPM bridge** on the same machine; the dashboard talks to it over `http://127.0.0.1` only.

```powershell
# Terminal 1 — API
python -m api.server

# Terminal 2 — TPM bridge (uses TPMManager: real TPM if TRUSTAUTH_TPM=real, else software)
python -m tpm_bridge.server
```

Open `http://localhost:8000/`, set **TPM bridge** to `http://127.0.0.1:8740` (default). When the bridge is **online**, Register/Login use **TPM signing** via the helper. If the bridge is **offline**, the dashboard falls back to **Web Crypto** in the browser.

Environment (optional): `TRUSTAUTH_TPM_BRIDGE_HOST`, `TRUSTAUTH_TPM_BRIDGE_PORT` (default `8740`).

Without the bridge, the dashboard uses **Web Crypto** only (keys in the browser). The **Python CLI** (`python -m client.client`) can still use **real TPM** directly without the bridge.

## Real TPM 2.0 (Python client)

1. Use **Linux or WSL2** with a visible TPM (hardware `/dev/tpmrm0` or **swtpm** simulator).
2. Install system TPM2 TSS libraries (e.g. Ubuntu: `sudo apt install tpm2-tools libtss2-dev` as needed for your distro).
3. Install the optional Python binding:
   ```bash
   pip install -r requirements-tpm.txt
   ```
4. Force real TPM (fail if unavailable):
   ```bash
   export TRUSTAUTH_TPM=real
   # optional: swtpm simulator
   # export TRUSTAUTH_TPM_TCTI=swtpm:host=127.0.0.1,port=2321
   python -m client.client
   ```
5. The client saves the TPM key blob to `trustauth_tpm_key.pem` and `trustauth_client_state.json` (device id). **Keep these private**; they bind this machine to your account.

If `TRUSTAUTH_TPM=auto` (default), the client uses real TPM when `tpm2-pytss` works; otherwise it falls back to software RSA (same wire format as the server).

**Note:** `tpm2-pytss` is often unavailable on **Windows Python** via pip; use **WSL2** or Linux for real TPM integration.

## Run Client
```powershell
python -m client.client
```

## Run Tests
```powershell
pytest -q
```
