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

    key = Column(String, primary_key=True, index=True)
    hwid = Column(String, nullable=True)
    nickname = Column(String, nullable=True)
    active = Column(Boolean, default=True)


class LicenseLog(Base):
    __tablename__ = "license_logs"

    id = Column(String, primary_key=True, default=lambda: secrets.token_hex(8))
    key = Column(String)
    nickname = Column(String)
    hwid = Column(String)
    status = Column(String)  # binded | ok | invalid_key | hwid_mismatch
    ip = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(
    title="License Server",
    version="1.1.0"
)

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
def verify(data: VerifyRequest, request: Request):
    db = SessionLocal()
    ip = request.client.host if request.client else "unknown"

    def log(status: str):
        db.add(
            LicenseLog(
                key=data.key,
                nickname=data.nickname,
                hwid=(data.hwid[:16] + "...") if data.hwid else None,
                status=status,
                ip=ip
            )
        )
        db.commit()

    try:
        lic = db.query(License).filter(License.key == data.key).first()

        if not lic or not lic.active:
            log("invalid_key")
            raise HTTPException(status_code=403, detail="invalid")

        # 🔐 первый запуск — биндим
        if lic.hwid is None:
            lic.hwid = data.hwid
            lic.nickname = data.nickname
            db.commit()
            log("binded")
            return {"status": "binded"}

        if lic.hwid != data.hwid:
            log("hwid_mismatch")
            raise HTTPException(status_code=403, detail="hwid_mismatch")

        # ✅ валидная лицензия
        log("ok")
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


@app.get("/admin/logs")
def get_logs(limit: int = 20):
    db = SessionLocal()
    try:
        return [
            {
                "time": l.created_at.isoformat(),
                "key": l.key,
                "nickname": l.nickname,
                "status": l.status,
                "ip": l.ip
            }
            for l in (
                db.query(LicenseLog)
                .order_by(LicenseLog.created_at.desc())
                .limit(limit)
                .all()
            )
        ]
    finally:
        db.close()


@app.get("/")
def root():
    return {"status": "ok"}

