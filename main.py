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
    role = Column(String)  # "root" | "admin"


Base.metadata.create_all(bind=engine)

# ================== FASTAPI ==================

app = FastAPI(title="StaffHelp API", version="4.0.0")

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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ================== ADMIN HELPERS ==================

def is_admin(db, user_id: int):
    return db.query(Admin).filter(Admin.user_id == str(user_id)).first()

def is_root(db, user_id: int):
    return db.query(Admin).filter(
        Admin.user_id == str(user_id),
        Admin.role == "root"
    ).first()

# ================== ADMIN API ==================

@app.post("/admin/check")
async def check_admin(request: Request):
    data = await request.json()
    user_id = str(data.get("user_id"))

    db = SessionLocal()
    try:
        admin = db.query(Admin).filter(Admin.user_id == user_id).first()
        if not admin:
            return {"role": None}
        return {"role": admin.role}
    finally:
        db.close()


@app.post("/admin/add")
async def add_admin(request: Request):
    data = await request.json()
    user_id = str(data["user_id"])
    role = data.get("role", "admin")

    db = SessionLocal()
    try:
        if db.query(Admin).filter(Admin.user_id == user_id).first():
            raise HTTPException(400, "Already admin")

        db.add(Admin(user_id=user_id, role=role))
        db.commit()
        return {"status": "ok"}
    finally:
        db.close()


@app.post("/admin/remove")
async def remove_admin(request: Request):
    data = await request.json()
    user_id = str(data["user_id"])

    db = SessionLocal()
    try:
        admin = db.query(Admin).filter(Admin.user_id == user_id).first()
        if not admin:
            raise HTTPException(404, "Not admin")

        db.delete(admin)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()


@app.get("/admin/list")
async def list_admins():
    db = SessionLocal()
    try:
        return [
            {"user_id": a.user_id, "role": a.role}
            for a in db.query(Admin).all()
        ]
    finally:
        db.close()

# ================== LICENSE API ==================

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

# ================== ROOT ==================

@app.get("/")
async def root():
    return {"status": "ok"}
