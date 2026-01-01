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

    user_id = Column(String, primary_key=True)
    role = Column(String)  # root | admin


Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(title="StaffHelp API", version="3.2.0")

# ================== UTILS ==================

def generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

def safe_int(v, d=0):
    try:
        return int(v)
    except:
        return d

# ================== ADMINS API ==================

@app.get("/admin/admins")
def list_admins():
    db = SessionLocal()
    try:
        return [
            {"user_id": a.user_id, "role": a.role}
            for a in db.query(Admin).all()
        ]
    finally:
        db.close()


@app.post("/admin/addadmin")
async def add_admin(request: Request):
    data = await request.json()
    uid = str(data.get("user_id"))
    role = data.get("role", "admin")

    if role not in ("admin", "root"):
        raise HTTPException(400, "invalid role")

    db = SessionLocal()
    try:
        if db.query(Admin).filter(Admin.user_id == uid).first():
            raise HTTPException(400, "already exists")

        db.add(Admin(user_id=uid, role=role))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.post("/admin/deladmin")
async def del_admin(request: Request):
    data = await request.json()
    uid = str(data.get("user_id"))

    db = SessionLocal()
    try:
        a = db.query(Admin).filter(Admin.user_id == uid).first()
        if not a:
            raise HTTPException(404, "not found")

        db.delete(a)
        db.commit()
        return {"status": "deleted"}
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
        raise HTTPException(400, "invalid request")

    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == key).first()
        if not lic or not lic.active:
            raise HTTPException(403, "invalid key")

        if lic.hwid is None:
            lic.hwid = hwid
            lic.nickname = nickname
            db.commit()
            return {"status": "binded"}

        if lic.hwid != hwid:
            raise HTTPException(403, "hwid mismatch")

        return {"status": "ok"}
    finally:
        db.close()

# ================== LICENSE ==================

@app.post("/admin/genkey")
def genkey():
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
    key = (await request.json()).get("key")
    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == key).first()
        if not lic:
            raise HTTPException(404, "not found")
        db.delete(lic)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()


@app.get("/admin/list")
def list_keys():
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
    except:
        return {"status": "ignored"}

    stats = data.get("current", data)
    staff = data.get("staffNickname") or data.get("staff") or "UNKNOWN"
    date = stats.get("date")

    db = SessionLocal()
    try:
        s = (
            db.query(StaffStats)
            .filter(StaffStats.staff == staff, StaffStats.date == date)
            .first()
        )

        if not s:
            s = StaffStats(staff=staff, date=date)
            db.add(s)

        s.bans = safe_int(stats.get("bans"))
        s.mutes = safe_int(stats.get("mutes"))
        s.total = safe_int(stats.get("total"), s.bans + s.mutes)
        s.updated_at = datetime.utcnow()

        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.get("/admin/stats")
def get_stats(date: str | None = None):
    db = SessionLocal()
    try:
        q = db.query(StaffStats)
        if date:
            q = q.filter(StaffStats.date == date)
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


@app.get("/")
def root():
    return {"status": "ok"}
