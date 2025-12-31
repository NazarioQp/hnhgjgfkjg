import os
import secrets
import string
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Boolean,
    DateTime
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ================== DATABASE ==================

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
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


Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(title="StaffHelp API", version="2.1.0")

# ================== SCHEMAS ==================

class VerifyRequest(BaseModel):
    key: str
    hwid: str
    nickname: str | None = None

class KeyRequest(BaseModel):
    key: str

# ================== UTILS ==================

def generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

# ================== LICENSE VERIFY ==================

@app.post("/verify")
def verify(data: VerifyRequest, request: Request):
    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == data.key).first()

        if not lic or not lic.active:
            raise HTTPException(status_code=403, detail="invalid_key")

        # первый запуск → биндим
        if lic.hwid is None:
            lic.hwid = data.hwid
            lic.nickname = data.nickname
            db.commit()
            return {"status": "binded"}

        # hwid не совпал
        if lic.hwid != data.hwid:
            raise HTTPException(status_code=403, detail="hwid_mismatch")

        return {"status": "ok"}

    finally:
        db.close()

# ================== ADMIN LICENSE ==================

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
def revoke(data: KeyRequest):
    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == data.key).first()
        if not lic:
            raise HTTPException(status_code=404, detail="not found")

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
                "active": l.active
            }
            for l in db.query(License).all()
        ]
    finally:
        db.close()

# ================== STATS ==================

@app.post("/stats/report")
async def report_stats(request: Request):
    data = await request.json()

    staff = data.get("staff")
    date = data.get("date")
    bans = int(data.get("bans", 0))
    mutes = int(data.get("mutes", 0))
    total = int(data.get("total", bans + mutes))

    if not staff or not date:
        raise HTTPException(status_code=422, detail="staff and date required")

    db = SessionLocal()
    try:
        stat = (
            db.query(StaffStats)
            .filter(StaffStats.staff == staff, StaffStats.date == date)
            .first()
        )

        if stat:
            stat.bans = bans
            stat.mutes = mutes
            stat.total = total
            stat.updated_at = datetime.utcnow()
        else:
            db.add(
                StaffStats(
                    staff=staff,
                    date=date,
                    bans=bans,
                    mutes=mutes,
                    total=total
                )
            )

        db.commit()
        return {"status": "ok"}
    finally:
        db.close()

# ================== ADMIN STATS ==================

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
                "total": s.total
            }
            for s in q.order_by(StaffStats.total.desc()).all()
        ]
    finally:
        db.close()

# ================== ROOT ==================

@app.get("/")
def root():
    return {"status": "ok"}
