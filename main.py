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
    role = Column(String)  # "root" | "admin"


Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(title="StaffHelp API", version="3.2.0")

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

# ================== ADMIN LICENSE ==================

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

    if not key:
        raise HTTPException(400, "key required")

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

# ================== STATS REPORT ==================

@app.post("/stats/report")
async def report_stats(request: Request):
    raw = await request.body()
    if not raw:
        return {"status": "ignored"}

    data = None
    try:
        data = json.loads(raw.decode())
    except Exception:
        try:
            text = raw.decode(errors="ignore")
            s, e = text.find("{"), text.rfind("}")
            if s != -1 and e != -1:
                data = json.loads(text[s:e+1])
        except Exception:
            return {"status": "ignored"}

    if not isinstance(data, dict):
        return {"status": "ignored"}

    stats = data.get("current", data)

    staff = data.get("staffNickname") or data.get("staff") or "UNKNOWN"
    date = stats.get("date") or stats.get("Дата")

    if not date:
        return {"status": "ignored"}

    bans = safe_int(stats.get("bans") or stats.get("Банов"))
    mutes = safe_int(stats.get("mutes") or stats.get("Мутов"))
    total = safe_int(stats.get("total") or stats.get("Всего"), bans + mutes)

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

# ================== ADMIN STATS ==================

@app.get("/admin/stats")
async def get_stats(date: str | None = None):
    db = SessionLocal()
    try:
        q = db.query(StaffStats)
        if date:
            q = q.filter_by(date=date)
        return [
            {
                "staff": s.staff,
                "date": s.date,
                "bans": s.bans,
                "mutes": s.mutes,
                "total": s.total,
            }
            for s in q.order_by(StaffStats.total.desc()).all()
        ]
    finally:
        db.close()

@app.get("/")
async def root():
    return {"status": "ok"}
