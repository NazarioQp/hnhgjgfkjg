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

print("DB URL:", DATABASE_URL)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,   # ✅ проверяет соединение перед использованием
    pool_recycle=1800,    # ✅ пересоздаёт соединение каждые 30 минут
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

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

app = FastAPI(title="StaffHelp API", version="3.1.0")

# ================== UTILS ==================

def generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

def safe_int(value, default=0) -> int:
    try:
        return int(value)
    except Exception:
        return default

# ================== VERIFY ==================

@app.post("/verify")
async def verify(request: Request):
    data = await request.json()

    key = data.get("key")
    hwid = data.get("hwid")
    nickname = data.get("nickname")

    if not key or not hwid:
        raise HTTPException(status_code=400, detail="invalid_request")

    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == key).first()

        if not lic or not lic.active:
            raise HTTPException(status_code=403, detail="invalid_key")

        if lic.hwid is None:
            lic.hwid = hwid
            lic.nickname = nickname
            db.commit()
            return {"status": "binded"}

        if lic.hwid != hwid:
            raise HTTPException(status_code=403, detail="hwid_mismatch")

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
        raise HTTPException(status_code=400, detail="key required")

    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == key).first()
        if not lic:
            raise HTTPException(status_code=404, detail="not found")

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

# ================== STATS REPORT (UPSERT) ==================

@app.post("/stats/report")
async def report_stats(request: Request):
    raw = await request.body()

    if not raw:
        return {"status": "ignored"}

    data = None

    # 1️⃣ JSON
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        pass

    # 2️⃣ multipart fallback
    if data is None:
        try:
            text = raw.decode("utf-8", errors="ignore")
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                data = json.loads(text[start:end + 1])
        except Exception:
            return {"status": "ignored"}

    if not isinstance(data, dict):
        return {"status": "ignored"}

    stats = data.get("current") if isinstance(data.get("current"), dict) else data

    staff = (
        data.get("staffNickname")
        or data.get("staff")
        or "UNKNOWN"
    )

    date = stats.get("date") or stats.get("Дата")
    bans = stats.get("bans") or stats.get("Банов")
    mutes = stats.get("mutes") or stats.get("Мутов")
    total = stats.get("total") or stats.get("Всего")

    if not date:
        print("NO DATE IN STATS:", stats)
        return {"status": "ignored"}

    bans = safe_int(bans)
    mutes = safe_int(mutes)
    total = safe_int(total, bans + mutes)

    db = SessionLocal()
    try:
        stat = (
            db.query(StaffStats)
            .filter(
                StaffStats.staff == staff,
                StaffStats.date == date,
            )
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
                    total=total,
                )
            )

        db.commit()
        print("✅ STATS UPSERT:", staff, date, bans, mutes, total)
        return {"status": "ok"}
    except Exception as e:
        print("DB ERROR:", e)
        return {"status": "error"}
    finally:
        db.close()

# ================== ADMIN STATS ==================

@app.get("/admin/stats")
async def get_stats(date: str | None = None):
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
            for s in q.order_by(StaffStats.total.desc()).all()
        ]
    finally:
        db.close()

# ================== ROOT ==================

@app.get("/")
async def root():
    return {"status": "ok"}
