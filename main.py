import json
import os
import secrets
import string
from datetime import datetime
from fastapi import UploadFile, File

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
print("DB URL:", DATABASE_URL)

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

app = FastAPI(title="StaffHelp API", version="2.3.0")

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

def safe_int(value, default=0) -> int:
    try:
        return int(value)
    except Exception:
        return default

# ================== LICENSE VERIFY ==================

@app.post("/verify")
def verify(data: VerifyRequest):
    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == data.key).first()

        if not lic or not lic.active:
            raise HTTPException(status_code=403, detail="invalid_key")

        if lic.hwid is None:
            lic.hwid = data.hwid
            lic.nickname = data.nickname
            db.commit()
            return {"status": "binded"}

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

# ================== STATS (ANTI-500 VERSION) ==================
    @app.post("/stats/report")
async def report_stats(request: Request):
    print("===== STATS REQUEST START =====")

    try:
        form = await request.form()
        print("FORM KEYS:", list(form.keys()))
        for k, v in form.items():
            if hasattr(v, "filename"):
                content = await v.read()
                print("FILE CONTENT:", content.decode("utf-8", errors="ignore"))
    except Exception as e:
        print("FORM ERROR:", e)

    try:
        data = await request.json()
        print("JSON BODY:", data)
    except Exception:
        print("NO JSON BODY")

    print("===== STATS REQUEST END =====")
    return {"status": "debug"}


    # 3️⃣ Если пришёл весь statistics.json
    if "current" in data and isinstance(data["current"], dict):
        current = data["current"]
    else:
        current = data

    # staff (включая staffNickname)
    staff = (
        data.get("staff")
        or data.get("staffNickname")
        or data.get("nickname")
        or data.get("player")
        or "UNKNOWN"
    )

    # RU / EN ключи
    date = current.get("date") or current.get("Дата")
    bans = current.get("bans") or current.get("Банов")
    mutes = current.get("mutes") or current.get("Мутов")
    total = current.get("total") or current.get("Всего")

    try:
        bans = int(bans or 0)
        mutes = int(mutes or 0)
        total = int(total or (bans + mutes))
    except Exception as e:
        print("NUMBER PARSE ERROR:", e)
        return {"status": "ignored", "reason": "invalid numbers"}

    if not date:
        print("NO DATE")
        return {"status": "ignored", "reason": "no date"}

    db = SessionLocal()
    try:
        stat = (
            db.query(StaffStats)
            .filter(
                StaffStats.staff == staff,
                StaffStats.date == date
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
                    total=total
                )
            )

        db.commit()
        print("✅ STATS SAVED:", staff, date, bans, mutes, total)
        return {"status": "ok"}
    except Exception as e:
        print("DB ERROR:", e)
        return {"status": "error"}
    finally:
        db.close()


# ================== ROOT ==================

@app.get("/")
def root():
    return {"status": "ok"}
