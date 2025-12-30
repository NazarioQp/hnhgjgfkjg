import os
import secrets
import string
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Boolean
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ================== CONFIG ==================

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()

# ================== MODEL ==================

class License(Base):
    __tablename__ = "licenses"

    key = Column(String, primary_key=True, index=True)
    hwid = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    active = Column(Boolean, default=True)

Base.metadata.create_all(bind=engine)

# ================== APP ==================

app = FastAPI(title="License Server")

# ================== UTILS ==================

def generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

# ================== SCHEMAS ==================

class VerifyRequest(BaseModel):
    key: str
    hwid: str
    nickname: Optional[str] = None

class KeyRequest(BaseModel):
    key: str

# ================== ROUTES ==================

@app.post("/verify")
def verify(req: VerifyRequest):
    db = SessionLocal()
    lic = db.query(License).filter(License.key == req.key).first()

    if not lic or not lic.active:
        db.close()
        raise HTTPException(status_code=403, detail="invalid")

    # первый запуск → привязка
    if lic.hwid is None:
        lic.hwid = req.hwid
        lic.nickname = req.nickname
        db.commit()
        db.close()
        return {"status": "binded"}

    # HWID не совпал
    if lic.hwid != req.hwid:
        db.close()
        raise HTTPException(status_code=403, detail="hwid_mismatch")

    db.close()
    return {"status": "ok"}

# ================== ADMIN ==================

@app.post("/admin/genkey")
def admin_genkey():
    db = SessionLocal()
    key = generate_key()
    lic = License(key=key)
    db.add(lic)
    db.commit()
    db.close()
    return {"key": key}

@app.post("/admin/revoke")
def admin_revoke(req: KeyRequest):
    db = SessionLocal()
    lic = db.query(License).filter(License.key == req.key).first()

    if not lic:
        db.close()
        raise HTTPException(status_code=404, detail="not_found")

    db.delete(lic)
    db.commit()
    db.close()
    return {"status": "deleted"}

@app.get("/admin/list")
def admin_list():
    db = SessionLocal()
    licenses = db.query(License).all()

    result = [
        {
            "key": l.key,
            "hwid": l.hwid,
            "nickname": l.nickname,
            "active": l.active
        }
        for l in licenses
    ]

    db.close()
    return result

# ================== ROOT ==================

@app.get("/")
def root():
    return {"status": "ok"}
