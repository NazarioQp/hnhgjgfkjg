import os
import json
import secrets
import string
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
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
    updated_at = Column(DateTime, default=datetime.utcnow)


class Admin(Base):
    __tablename__ = "admins"

    user_id = Column(BigInteger, primary_key=True)
    role = Column(String)  # root | admin | kyrator


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
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(title="StaffHelp API", version="3.4.0")

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

# ================== ADMINS API ==================

@app.get("/admin/admins")
async def list_admins():
    db = SessionLocal()
    try:
        return [{"user_id": a.user_id, "role": a.role} for a in db.query(Admin).all()]
    finally:
        db.close()


@app.post("/admin/addadmin")
async def add_admin(data: dict):
    user_id = data.get("user_id")
    role = data.get("role", "admin")

    if role not in ("admin", "root", "kyrator"):
        raise HTTPException(400, "invalid role")

    db = SessionLocal()
    try:
        if db.query(Admin).filter_by(user_id=user_id).first():
            raise HTTPException(409, "already exists")

        db.add(Admin(user_id=user_id, role=role))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.post("/admin/deladmin")
async def del_admin(data: dict):
    user_id = data.get("user_id")

    db = SessionLocal()
    try:
        adm = db.query(Admin).filter_by(user_id=user_id).first()
        if not adm:
            raise HTTPException(404, "not found")

        db.delete(adm)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()

# ================== LOGGING ==================

@app.post("/admin/logs")
async def toggle_logs(data: dict):
    enabled = data.get("enabled")

    if not isinstance(enabled, bool):
        raise HTTPException(400, "enabled must be boolean")

    db = SessionLocal()
    try:
        cfg = db.query(LogConfig).get(1)
        if not cfg:
            cfg = LogConfig(enabled=enabled)
            db.add(cfg)
        else:
            cfg.enabled = enabled
        db.commit()
        return {"enabled": cfg.enabled}
    finally:
        db.close()


@app.post("/admin/log_message")
async def log_message(data: dict):
    db = SessionLocal()
    try:
        if not logs_enabled(db):
            return {"status": "disabled"}

        db.add(MessageLog(
            user_id=data["user_id"],
            role=data["role"],
            text=data["text"],
        ))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()

# ================== VERIFY ==================

@app.post("/verify")
async def verify(request: Request):
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

# ================== LICENSE ADMIN ==================

@app.post("/admin/genkey")
async def genkey():
    db = SessionLocal()
    try:
        key = generate_key()
        db.add(License(key=key))
        db.commit()
        return {"key": key}
    finally:
        db.close()


@app.post("/admin/revoke")
async def revoke(request: Request):
    data = await request.json()
    key = data.get("key")

    db = SessionLocal()
    try:
        lic = db.query(License).filter_by(key=key).first()
        if not lic:
            raise HTTPException(404, "not found")
        db.delete(lic)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()


@app.get("/admin/list")
async def list_keys():
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

# ================== STATS ==================

@app.post("/stats/report")
async def report_stats(request: Request):
    raw = await request.body()
    if not raw:
        return {"status": "ignored"}

    try:
        data = json.loads(raw.decode())
    except Exception:
        return {"status": "ignored"}

    stats = data.get("current", data)
    staff = data.get("staffNickname") or data.get("staff") or "UNKNOWN"
    date = stats.get("date")
    if not date:
        return {"status": "ignored"}

    bans = safe_int(stats.get("bans"))
    mutes = safe_int(stats.get("mutes"))
    total = bans + mutes

    db = SessionLocal()
    try:
        row = db.query(StaffStats).filter_by(staff=staff, date=date).first()
        if row:
            row.bans = bans
            row.mutes = mutes
            row.total = total
            row.updated_at = datetime.utcnow()
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

# ================== ROOT ==================

@app.get("/")
async def root():
    return {"status": "ok"}
