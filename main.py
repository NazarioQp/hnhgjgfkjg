import os
import json
import secrets
import string
import asyncio
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import APIKeyHeader
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    BigInteger,
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ================== TIMEZONE ==================

MSK = ZoneInfo("Europe/Moscow")

def now_msk() -> datetime:
    return datetime.now(MSK)

def today_msk() -> str:
    return now_msk().strftime("%Y-%m-%d")

# ================== SECURITY ==================

SERVER_API_KEY = os.getenv("SERVER_API_KEY")

if not SERVER_API_KEY:
    raise RuntimeError("SERVER_API_KEY is not set")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def require_api_key(api_key: str = Depends(api_key_header)):
    if api_key != SERVER_API_KEY:
        raise HTTPException(403, "invalid_api_key")
    return True

# ================== DATABASE ==================

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ================== MODELS ==================

class License(Base):
    __tablename__ = "licenses"

    key = Column(String, primary_key=True)
    hwid = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    active = Column(Boolean, default=True)


class StaffStats(Base):
    __tablename__ = "staff_stats"

    id = Column(String, primary_key=True, default=lambda: secrets.token_hex(8))
    staff = Column(String, index=True)
    date = Column(String, index=True)
    bans = Column(Integer, default=0)
    mutes = Column(Integer, default=0)
    total = Column(Integer, default=0)
    updated_at = Column(DateTime, default=lambda: now_msk())


class Admin(Base):
    __tablename__ = "admins"

    user_id = Column(BigInteger, primary_key=True)
    role = Column(String)


class LogConfig(Base):
    __tablename__ = "log_config"

    id = Column(Integer, primary_key=True, default=1)
    enabled = Column(Boolean, default=False)


class MessageLog(Base):
    __tablename__ = "message_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(BigInteger, index=True)
    role = Column(String)
    text = Column(String)
    chat_id = Column(BigInteger, index=True)
    created_at = Column(DateTime, default=lambda: now_msk())


class LogChatBlacklist(Base):
    __tablename__ = "log_chat_blacklist"

    chat_id = Column(BigInteger, primary_key=True)


Base.metadata.create_all(bind=engine)

# ================== AUTO MIGRATION ==================

from sqlalchemy import inspect, text

def auto_migrate():

    inspector = inspect(engine)

    with engine.connect() as conn:

        # message_logs.chat_id
        if "message_logs" in inspector.get_table_names():

            columns = [c["name"] for c in inspector.get_columns("message_logs")]

            if "chat_id" not in columns:

                print("AUTO MIGRATE: adding message_logs.chat_id")

                conn.execute(text(
                    "ALTER TABLE message_logs ADD COLUMN chat_id BIGINT"
                ))

                conn.commit()

        # message_logs.created_at
        if "message_logs" in inspector.get_table_names():

            columns = [c["name"] for c in inspector.get_columns("message_logs")]

            if "created_at" not in columns:

                print("AUTO MIGRATE: adding message_logs.created_at")

                conn.execute(text(
                    "ALTER TABLE message_logs ADD COLUMN created_at TIMESTAMP"
                ))

                conn.commit()


# ================== FASTAPI ==================

app = FastAPI(title="StaffHelp API", version="4.0.0-secure")

# ================== UTILS ==================

def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

def safe_int(v, d=0):
    try:
        return int(v)
    except Exception:
        return d

def logs_enabled(db):
    cfg = db.query(LogConfig).get(1)
    return bool(cfg and cfg.enabled)

def chat_blacklisted(db, chat_id: int) -> bool:
    return db.query(LogChatBlacklist).filter_by(chat_id=chat_id).first() is not None

# ================== TIME API ==================

@app.get("/time")
async def server_time():
    now = now_msk()
    return {
        "date": now.strftime("%Y-%m-%d"),
        "datetime": now.isoformat(),
        "timezone": "Europe/Moscow"
    }

# ================== ADMINS ==================

@app.get("/admin/admins")
async def list_admins(_: bool = Depends(require_api_key)):
    db = SessionLocal()
    try:
        return [{"user_id": a.user_id, "role": a.role} for a in db.query(Admin).all()]
    finally:
        db.close()


@app.post("/admin/addadmin")
async def add_admin(data: dict, _: bool = Depends(require_api_key)):
    db = SessionLocal()
    try:
        db.add(Admin(user_id=data["user_id"], role=data["role"]))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.post("/admin/deladmin")
async def del_admin(data: dict, _: bool = Depends(require_api_key)):
    db = SessionLocal()
    try:
        adm = db.query(Admin).filter_by(user_id=data["user_id"]).first()
        if not adm:
            raise HTTPException(404, "not found")
        db.delete(adm)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()

# ================== LICENSES ==================

@app.post("/admin/genkey")
async def genkey(_: bool = Depends(require_api_key)):
    db = SessionLocal()
    try:
        key = generate_key()
        db.add(License(key=key))
        db.commit()
        return {"key": key}
    finally:
        db.close()


@app.post("/admin/revoke")
async def revoke(data: dict, _: bool = Depends(require_api_key)):
    db = SessionLocal()
    try:
        lic = db.query(License).filter_by(key=data["key"]).first()
        if not lic:
            raise HTTPException(404, "not found")
        db.delete(lic)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()


@app.get("/admin/list")
async def list_keys(_: bool = Depends(require_api_key)):
    db = SessionLocal()
    try:
        return [
            {
                "key": l.key,
                "hwid": l.hwid,
                "nickname": l.nickname,
                "active": l.active,
            }
            for l in db.query(License).all()
        ]
    finally:
        db.close()

# ================== VERIFY ==================

@app.post("/verify")
async def verify(request: Request, _: bool = Depends(require_api_key)):

    data = await request.json()

    key = data.get("key")
    hwid = data.get("hwid")
    nickname = data.get("nickname")

    if not key or not hwid:
        raise HTTPException(400, "invalid_request")

    db = SessionLocal()

    try:

        lic = db.query(License).filter_by(key=key).first()

        if not lic or not lic.active:
            raise HTTPException(403, "invalid_key")

        if lic.hwid is None:

            lic.hwid = hwid
            lic.nickname = nickname

            db.commit()

            return {"status": "binded"}

        if lic.hwid != hwid:
            raise HTTPException(403, "hwid_mismatch")

        return {"status": "ok"}

    finally:
        db.close()

# ================== LOGGING ==================

@app.post("/admin/logs")
async def toggle_logs(data: dict, _: bool = Depends(require_api_key)):

    db = SessionLocal()

    try:

        cfg = db.query(LogConfig).get(1) or LogConfig(enabled=data["enabled"])

        cfg.enabled = data["enabled"]

        db.add(cfg)

        db.commit()

        return {"enabled": cfg.enabled}

    finally:
        db.close()


@app.post("/admin/log_message")
async def log_message(data: dict, _: bool = Depends(require_api_key)):

    db = SessionLocal()

    try:

        if not logs_enabled(db):
            return {"status": "disabled"}

        if chat_blacklisted(db, data["chat_id"]):
            return {"status": "blacklisted"}

        db.add(MessageLog(**data))

        db.commit()

        return {"status": "ok"}

    finally:
        db.close()

# ================== STATS ==================

@app.get("/admin/stats")
async def get_stats(date: str | None = None, staff: str | None = None, _: bool = Depends(require_api_key)):

    db = SessionLocal()

    try:

        q = db.query(StaffStats)

        if date:
            q = q.filter_by(date=date)

        if staff:
            q = q.filter(StaffStats.staff.ilike(f"%{staff}%"))

        return [
            {
                "staff": s.staff,
                "date": s.date,
                "bans": s.bans,
                "mutes": s.mutes,
                "total": s.total,
            }
            for s in q.all()
        ]

    finally:
        db.close()


@app.post("/stats/report")
async def report_stats(request: Request, _: bool = Depends(require_api_key)):

    raw = await request.body()

    if not raw:
        return {"status": "ignored"}

    try:
        data = json.loads(raw.decode())
    except Exception:
        return {"status": "ignored"}

    stats = data.get("current", data)

    staff = data.get("staffNickname") or data.get("staff") or "UNKNOWN"

    date = today_msk()

    bans = safe_int(stats.get("bans"))
    mutes = safe_int(stats.get("mutes"))

    total = bans + mutes

    db = SessionLocal()

    try:

        row = db.query(StaffStats).filter_by(
            staff=staff,
            date=date
        ).first()

        if row:

            row.bans = bans
            row.mutes = mutes
            row.total = total
            row.updated_at = now_msk()

        else:

            db.add(StaffStats(
                staff=staff,
                date=date,
                bans=bans,
                mutes=mutes,
                total=total,
            ))

        db.commit()

        return {"status": "ok"}

    finally:
        db.close()

# ================== AUTO CLEANUP LOGS ==================

async def cleanup_logs_loop():

    while True:

        await asyncio.sleep(3600)

        db = SessionLocal()

        try:

            threshold = now_msk() - timedelta(hours=12)

            db.query(MessageLog).filter(
                MessageLog.created_at < threshold
            ).delete()

            db.commit()

        finally:
            db.close()

@app.on_event("startup")
async def startup():
    asyncio.create_task(cleanup_logs_loop())

@app.get("/")
async def root():
    return {"status": "ok"}
