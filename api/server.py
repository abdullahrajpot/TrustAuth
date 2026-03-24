import os
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from database.mongo import devices, ensure_indexes, logs, next_device_id, next_session_id, next_user_id, sessions, users
from tpm_manager.tpm_handler import TPMManager


load_dotenv()

APP_NAME = os.getenv("APP_NAME", "TrustAuth API")
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_EXPIRY_HOURS = int(os.getenv("TOKEN_EXPIRY_HOURS", "24"))
CHALLENGE_EXPIRY_SECONDS = int(os.getenv("CHALLENGE_EXPIRY_SECONDS", "300"))
CORS_ALLOWED_ORIGINS = [
    item.strip()
    for item in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8000").split(",")
    if item.strip()
]

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is required. Set it in your .env file.")

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title=APP_NAME, version="1.0.0", description="Hardware-backed authentication API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_challenges: Dict[str, dict] = {}


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    email: Optional[str] = None
    device_name: str = Field(min_length=1, max_length=100)
    device_type: str = "laptop"
    tpm_public_key: str = Field(min_length=64)
    pcr_values: list = []


class ChallengeRequest(BaseModel):
    device_id: int


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: int
    challenge_nonce: str
    signature: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_token(user_id: int, device_id: int) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "device_id": device_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=TOKEN_EXPIRY_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


def log_auth_event(user_id, device_id, action, success, ip, details="") -> None:
    logs.insert_one(
        {
            "user_id": user_id,
            "device_id": device_id,
            "action": action,
            "success": success,
            "ip_address": ip,
            "details": details,
            "created_at": datetime.utcnow(),
        }
    )


def get_current_payload(auth: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = decode_token(auth.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


@app.on_event("startup")
def on_startup() -> None:
    ensure_indexes()


@app.get("/api/health")
def health() -> dict:
    return {"status": "healthy", "time": datetime.utcnow().isoformat()}


@app.post("/api/register")
def register(data: RegisterRequest, req: Request) -> dict:
    try:
        if users.find_one({"username": data.username}):
            log_auth_event(None, None, "register", False, req.client.host, "username exists")
            raise HTTPException(status_code=400, detail="Username already exists")

        user_id = next_user_id()
        users.insert_one(
            {
                "id": user_id,
                "username": data.username,
                "password_hash": hash_password(data.password),
                "email": data.email,
                "created_at": datetime.utcnow(),
            }
        )

        device_id = next_device_id()
        devices.insert_one(
            {
                "id": device_id,
                "user_id": user_id,
                "device_name": data.device_name,
                "device_type": data.device_type,
                "public_key_pem": data.tpm_public_key,
                "pcr_measurements": data.pcr_values,
                "is_active": True,
                "last_used": None,
                "created_at": datetime.utcnow(),
            }
        )

        log_auth_event(user_id, device_id, "register", True, req.client.host)
        return {"success": True, "user_id": user_id, "device_id": device_id}
    except HTTPException:
        raise
    except Exception as exc:
        log_auth_event(None, None, "register", False, req.client.host, str(exc))
        raise HTTPException(status_code=500, detail="Registration failed")


@app.post("/api/challenge")
def get_challenge(data: ChallengeRequest) -> dict:
    device = devices.find_one({"id": data.device_id, "is_active": True})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found or inactive")

    challenge = secrets.token_hex(32)
    active_challenges[challenge] = {
        "device_id": device["id"],
        "user_id": device["user_id"],
        "expires_at": datetime.utcnow() + timedelta(seconds=CHALLENGE_EXPIRY_SECONDS),
    }
    return {"challenge": challenge, "expires_in": CHALLENGE_EXPIRY_SECONDS}


@app.post("/api/login")
def login(data: LoginRequest, req: Request) -> dict:
    user = users.find_one({"username": data.username})
    if not user or not verify_password(data.password, user["password_hash"]):
        log_auth_event(None, None, "login", False, req.client.host, "invalid credentials")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    device = devices.find_one({"id": data.device_id, "user_id": user["id"], "is_active": True})
    if not device:
        log_auth_event(user["id"], data.device_id, "login", False, req.client.host, "device inactive")
        raise HTTPException(status_code=401, detail="Device not authorized")

    challenge_data = active_challenges.get(data.challenge_nonce)
    if not challenge_data:
        raise HTTPException(status_code=401, detail="Invalid or expired challenge")

    if challenge_data["device_id"] != device["id"]:
        active_challenges.pop(data.challenge_nonce, None)
        raise HTTPException(status_code=401, detail="Challenge-device mismatch")

    if datetime.utcnow() > challenge_data["expires_at"]:
        active_challenges.pop(data.challenge_nonce, None)
        raise HTTPException(status_code=401, detail="Challenge expired")

    if not TPMManager.verify_signature(device["public_key_pem"], data.challenge_nonce, data.signature):
        active_challenges.pop(data.challenge_nonce, None)
        log_auth_event(user["id"], device["id"], "login", False, req.client.host, "invalid signature")
        raise HTTPException(status_code=401, detail="Invalid device signature")

    active_challenges.pop(data.challenge_nonce, None)
    token = create_token(user["id"], device["id"])
    devices.update_one({"id": device["id"]}, {"$set": {"last_used": datetime.utcnow()}})
    sessions.insert_one(
        {
            "id": next_session_id(),
            "user_id": user["id"],
            "device_id": device["id"],
            "token": token,
            "expires_at": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS),
            "created_at": datetime.utcnow(),
        }
    )

    log_auth_event(user["id"], device["id"], "login", True, req.client.host)
    return {
        "success": True,
        "token": token,
        "expires_in_hours": TOKEN_EXPIRY_HOURS,
        "user": {"id": user["id"], "username": user["username"], "email": user.get("email")},
    }


@app.get("/api/devices")
def list_devices(payload: dict = Depends(get_current_payload)) -> dict:
    user_id = int(payload["sub"])
    user_devices = list(devices.find({"user_id": user_id}, {"_id": 0}))
    return {
        "devices": [
            {
                "id": d["id"],
                "name": d["device_name"],
                "type": d["device_type"],
                "is_active": d["is_active"],
                "last_used": d["last_used"].isoformat() if d.get("last_used") else None,
                "created_at": d["created_at"].isoformat(),
            }
            for d in user_devices
        ]
    }


@app.delete("/api/devices/{device_id}")
def revoke_device(device_id: int, payload: dict = Depends(get_current_payload)) -> dict:
    user_id = int(payload["sub"])
    device = devices.find_one({"id": device_id, "user_id": user_id})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    devices.update_one({"id": device_id}, {"$set": {"is_active": False}})
    sessions.delete_many({"device_id": device_id})
    return {"success": True, "message": f"Device '{device['device_name']}' revoked"}


@app.post("/api/logout")
def logout(auth: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    sessions.delete_many({"token": auth.credentials})
    return {"success": True}


@app.get("/api/sessions")
def list_sessions(payload: dict = Depends(get_current_payload)) -> dict:
    user_id = int(payload["sub"])
    now = datetime.utcnow()
    active = list(sessions.find({"user_id": user_id, "expires_at": {"$gt": now}}, {"_id": 0}))
    out = []
    for s in active:
        dev = devices.find_one({"id": s["device_id"]}, {"_id": 0})
        out.append(
            {
                "session_id": s["id"],
                "device_id": s["device_id"],
                "device_name": dev["device_name"] if dev else "Unknown",
                "expires_at": s["expires_at"].isoformat(),
                "created_at": s["created_at"].isoformat(),
            }
        )
    return {"sessions": out}


_dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
if _dashboard_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=False)
