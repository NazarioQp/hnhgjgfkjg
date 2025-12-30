import os
import secrets
import string
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Boolean
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

    key = Column(String, primary_key=True, index=True)
    hwid = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    active = Column(Boolean, default=True)

Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(title="License Server")

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

# ================== ENDPOINTS ==================

@app.post("/verify")
def verify(data: VerifyRequest):
    db = SessionLocal()
    try:
        lic = db.query(License).filter(License.key == data.key).first()

        if not lic or not lic.active:
            raise HTTPException(status_code=403, detail="invalid")

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
