import os
from datetime import datetime

from dotenv import load_dotenv
from pymongo import ASCENDING, MongoClient
from pymongo.errors import PyMongoError


load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DB = os.getenv("MONGODB_DB", "trustauth")

client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
db = client[MONGODB_DB]

users = db["users"]
devices = db["devices"]
sessions = db["auth_sessions"]
logs = db["auth_logs"]
counters = db["counters"]


def _next_sequence(name: str) -> int:
    doc = counters.find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}, "$setOnInsert": {"created_at": datetime.utcnow()}},
        upsert=True,
        return_document=True,
    )
    return int(doc["seq"])


def next_user_id() -> int:
    return _next_sequence("user_id")


def next_device_id() -> int:
    return _next_sequence("device_id")


def next_session_id() -> int:
    return _next_sequence("session_id")


def ensure_indexes() -> None:
    try:
        users.create_index([("username", ASCENDING)], unique=True)
        devices.create_index([("user_id", ASCENDING)])
        devices.create_index([("id", ASCENDING)], unique=True)
        sessions.create_index([("token", ASCENDING)], unique=True)
        sessions.create_index([("user_id", ASCENDING)])
        sessions.create_index([("device_id", ASCENDING)])
        logs.create_index([("created_at", ASCENDING)])
    except PyMongoError:
        # Keep API process bootable even if MongoDB is down.
        pass
