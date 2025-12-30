import os
import secrets
import string
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# ================= CONFIG =================

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

# ================= DATABASE =================

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class License(Base):
    __tablename__ = "licenses"

    key = Column(String, primary_key=True)
    hwid = Column(String, nullable=True)
    mc_nick = Column(String, nullable=True)   # 👤 ник первого запуска
    active = Column(Boolean, default=True)

Base.metadata.create_all(engine)

# ================= APP =================

app = FastAPI(title="StaffHelp License Server")

# ================= UTILS =================

def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

# ================= ROUTES =================

@app.get("/")
def root():
    return {"status": "ok"}

# ---------- VERIFY (MOD) ----------

@app.post("/verify")
def verify(data: dict):
    key = data.get("key")
    hwid = data.get("hwid")
    nickname = data.get("nickname")

    if not key or not hwid:
        raise HTTPException(status_code=400, detail="key and hwid required")

    db = SessionLocal()
    lic = db.query(License).filter_by(key=key).first()

    if not lic or not lic.active:
        db.close()
        return JSONResponse({"status": "invalid"}, status_code=403)

    # 🔐 первый запуск — привязка HWID + ник
    if lic.hwid is None:
        lic.hwid = hwid
        lic.mc_nick = nickname
        db.commit()
        db.close()
        return {"status": "binded"}

    # ❌ другой компьютер
    if lic.hwid != hwid:
        db.close()
        return JSONResponse({"status": "hwid_mismatch"}, status_code=403)

    db.close()
    return {"status": "ok"}

# ---------- ADMIN ----------

@app.post("/admin/genkey")
def genkey():
    db = SessionLocal()

    key = generate_key()
    db.add(License(key=key))
    db.commit()
    db.close()

    return {"key": key}

@app.post("/admin/revoke")
def revoke(data: dict):
    key = data.get("key")
    if not key:
        raise HTTPException(status_code=400, detail="key required")

    db = SessionLocal()
    lic = db.query(License).filter_by(key=key).first()

    if not lic:
        db.close()
        raise HTTPException(status_code=404, detail="not found")

    db.delete(lic)
    db.commit()
    db.close()

    return {"status": "deleted"}

@app.get("/admin/list")
def list_keys():
    db = SessionLocal()
    result = [
        {
            "key": l.key,
            "hwid": l.hwid,
            "mc_nick": l.mc_nick,
            "active": l.active
        }
        for l in db.query(License).all()
    ]
    db.close()
    return result
