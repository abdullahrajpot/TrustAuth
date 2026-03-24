# TrustAuth - Hardware-Backed Authentication System

## 1. Project Summary

TrustAuth is an authentication system that binds user login to a trusted hardware device using TPM-based cryptographic keys. The goal is to reduce account takeover risk caused by stolen passwords by requiring both:

1. Something the user knows (password)
2. Something the user has (a trusted device with TPM key)

The system uses a challenge-response protocol to validate device possession before issuing a session token.

---

## 2. Problem Statement

Password-only authentication is vulnerable to phishing, credential leaks, and password reuse attacks. Standard MFA methods can still be bypassed in some cases (SIM swap, OTP interception, social engineering). TrustAuth addresses this gap by adding hardware trust as an authentication factor.

---

## 3. Project Objectives

### 3.1 Primary Objectives
- Build a secure login system that verifies both user credentials and trusted device identity.
- Integrate TPM for device-bound key generation and challenge signing.
- Provide device lifecycle management (register, list, revoke).
- Maintain authentication audit logs for monitoring and incident response.

### 3.2 Academic (FYP) Objectives
- Demonstrate practical implementation of hardware-backed authentication.
- Compare security posture with password-only authentication.
- Evaluate performance and usability of the proposed approach.

---

## 4. Scope

### 4.1 In Scope
- User registration with first trusted device
- Challenge generation and login verification flow
- Session token issuance and logout
- Device management dashboard/API
- Audit logging for security events

### 4.2 Out of Scope (Current Version)
- Full remote TPM attestation chain verification
- Cross-platform production installer
- Enterprise IAM integrations (SAML/OIDC)
- High-availability distributed deployment

---

## 5. Functional Requirements

| ID | Requirement | Priority | Status |
|---|---|---|---|
| FR-01 | User can register account with username/password | High | Implemented |
| FR-02 | User can register a trusted device with TPM public key | High | Implemented |
| FR-03 | System generates one-time challenge for login | High | Implemented |
| FR-04 | Device signs challenge using TPM private key | High | Implemented (client side) |
| FR-05 | Server verifies challenge ownership and expiry | High | Implemented |
| FR-06 | Server verifies TPM signature using stored public key | Critical | **Pending improvement** |
| FR-07 | Authenticated user can list registered devices | Medium | Implemented |
| FR-08 | Authenticated user can revoke lost/stolen device | High | Implemented |
| FR-09 | System records authentication events in audit logs | Medium | Implemented |
| FR-10 | User can logout and invalidate active session | Medium | Implemented |

---

## 6. Non-Functional Requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-01 | Security | Passwords must be stored with strong adaptive hashing (Argon2/bcrypt) |
| NFR-02 | Security | JWT secret keys must be externally configured and rotated |
| NFR-03 | Security | API must enforce strict CORS and input validation |
| NFR-04 | Reliability | Challenge must expire and be one-time-use only |
| NFR-05 | Performance | Login request should complete within acceptable latency target |
| NFR-06 | Maintainability | Codebase should be modular with clear API/client/TPM/database boundaries |
| NFR-07 | Auditability | Security events must be logged with timestamp and context |
| NFR-08 | Usability | Core authentication and device management flow must be simple to operate |

---

## 7. System Architecture

### 7.1 High-Level Components
- **Client Application**: Handles user interaction, TPM key operations, and API communication.
- **TPM Manager**: Interfaces with hardware TPM/software TPM emulator.
- **Auth API Server (FastAPI)**: Orchestrates registration, challenge, login, token/session control.
- **Database (SQLite)**: Stores users, devices, sessions, and audit logs.
- **Dashboard**: Displays device/session management functions.

### 7.2 Logical Flow
1. User registers with password and TPM-backed public key.
2. During login, server issues nonce challenge.
3. Device signs challenge with TPM private key.
4. Server validates credentials, challenge metadata, and signature.
5. Server issues JWT and stores active session metadata.

---

## 8. Data Design

### 8.1 Core Entities
- `User`: account identity and password hash
- `Device`: trusted device metadata and TPM public key
- `AuthSession`: token/session tracking
- `AuthLog`: security and audit event history

### 8.2 Recommended Improvements
- Add explicit foreign keys (`devices.user_id -> users.id`, etc.)
- Add indexes on `username`, `device_id`, `expires_at`
- Manage schema evolution using migrations (Alembic)

---

## 9. Security Design

### 9.1 Threats Considered
- Stolen passwords
- Replay of intercepted login payloads
- Unauthorized device usage
- Session token theft
- Brute-force login attempts

### 9.2 Current Controls
- Challenge nonce with expiry window
- Device activation status and revocation
- Session token expiration
- Authentication event logging

### 9.3 Mandatory Security Improvements
- Implement real TPM signature verification on server side
- Replace SHA-256 with Argon2/bcrypt for passwords
- Move secrets/config to environment variables (`.env`)
- Restrict CORS to trusted origins only
- Add login rate limiting and lockout policy
- Use HTTPS in deployment

---

## 10. Technology Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI, Uvicorn |
| Database | SQLite, SQLAlchemy |
| Crypto/Auth | TPM2 libraries, JWT |
| Client | Python CLI application |
| Dashboard | HTML/CSS/JS |
| Testing | Pytest (recommended) |

---

## 11. Setup and Installation

### 11.1 Prerequisites
- Python 3.10+
- `pip`
- TPM 2.0 device (recommended) or software TPM for development

### 11.2 Environment Setup (Windows PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install fastapi uvicorn sqlalchemy cryptography requests python-jose passlib tpm2-pytss
```

### 11.3 Run the API
```powershell
python api/server.py
```

### 11.4 Run the Client
```powershell
python client/client.py
```

---

## 12. API Overview

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/register` | POST | Register user and first trusted device |
| `/api/challenge` | POST | Get one-time challenge for login |
| `/api/login` | POST | Authenticate with password + device proof |
| `/api/devices` | GET | List user devices |
| `/api/devices/{device_id}` | DELETE | Revoke device |
| `/api/sessions` | GET | List active sessions |
| `/api/logout` | POST | Invalidate current session |
| `/api/health` | GET | Health check |

---

## 13. Testing Strategy (FYP Evidence)

### 13.1 Unit Tests
- Password hashing/verification behavior
- Challenge creation and expiry logic
- JWT creation/verification behavior

### 13.2 Integration Tests
- Register -> Challenge -> Login happy path
- Login failure cases (wrong password, expired challenge, revoked device)
- Device revocation effect on subsequent login

### 13.3 Security Tests
- Replay attempt with used challenge
- Brute-force simulation with rate limiting (after implementation)
- Token reuse after logout/revocation

### 13.4 Evidence to Include in Report
- API test result screenshots
- Test summary table (Passed/Failed)
- Performance timings for login endpoints

---

## 14. Evaluation Metrics

| Metric | Target | Measurement Method |
|---|---|---|
| Login success rate (valid cases) | >= 99% | Automated integration tests |
| Replay attack resistance | 100% blocked | Reuse challenge test |
| Average login latency | Define threshold (e.g., < 800 ms local) | Timed test runs |
| Device revocation effectiveness | 100% | Post-revocation login tests |

---

## 15. Deployment and Operations

### 15.1 Recommended Production Practices
- Use PostgreSQL instead of SQLite for production.
- Store secrets in environment variables (never hardcode).
- Deploy behind HTTPS reverse proxy (Nginx/Caddy).
- Configure backup and restore procedures.
- Add centralized logs and monitoring dashboard.

### 15.2 Configuration Checklist
- `JWT_SECRET`
- `JWT_ALGORITHM`
- `TOKEN_EXPIRY_HOURS`
- `CORS_ALLOWED_ORIGINS`
- `DATABASE_URL`

---

## 16. Current Limitations

- Signature verification is currently simplified and must be hardened.
- SQLite and in-memory challenge store are not ideal for distributed production.
- CORS and secret management need stricter security controls.
- TPM behavior may vary across hardware vendors/platforms.

---

## 17. Future Work

- Implement full public-key signature verification path.
- Add refresh tokens and session rotation.
- Add multi-device enrollment approval workflow.
- Add account recovery and secure device replacement process.
- Integrate remote attestation and policy-based trust scoring.
- Develop full frontend dashboard with role-based admin controls.

---

## 18. FYP Viva Demo Script

1. Show registration on trusted device.
2. Show successful login with challenge-response.
3. Show failed login from non-trusted/revoked context.
4. Revoke a device and demonstrate blocked access.
5. Show audit logs proving event traceability.
6. Present test results and security comparison summary.

---

## 19. Conclusion

TrustAuth demonstrates a practical approach to hardware-backed authentication by combining password verification with TPM-based device identity. The prototype validates the concept and includes core account, device, and session workflows. To reach production-grade quality and stronger academic impact, the next priority is strict signature verification, hardened credential storage, and deployment-level security controls.

---

## Appendix A - Suggested Repository Structure

```text
TrustAuth/
  api/
    server.py
  client/
    client.py
  database/
    models.py
  tpm_manager/
    tpm_handler.py
  dashboard/
    index.html
  tests/
  README.md
  project overview.md
```

## Appendix B - Submission Checklist

- [ ] Problem statement and objectives clearly defined
- [ ] FR/NFR tables completed
- [ ] Architecture and flow diagram included
- [ ] Security controls mapped to threats
- [ ] Test evidence attached (screenshots + results table)
- [ ] Performance evaluation completed
- [ ] Limitations and future work discussed
- [ ] Professional README and setup instructions verified