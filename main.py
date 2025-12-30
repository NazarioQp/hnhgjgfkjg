import os
import secrets
import string
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
Base = declarative_base()

class License(Base):
    __tablename__ = "licenses"

    key = Column(String, primary_key=True)
    hwid = Column(String, nullable=True)
    active = Column(Boolean, default=True)

Base.metadata.create_all(engine)

app = FastAPI()

def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(3)
    )

@app.post("/verify")
def verify(data: dict):
    key = data.get("key")
    hwid = data.get("hwid")

    db = Session()
    lic = db.query(License).filter_by(key=key).first()

    if not lic or not lic.active:
        db.close()
        return JSONResponse({"status": "invalid"}, status_code=403)

    if lic.hwid is None:
        lic.hwid = hwid
        db.commit()
        db.close()
        return {"status": "binded"}

    if lic.hwid != hwid:
        db.close()
        return JSONResponse({"status": "hwid_mismatch"}, status_code=403)

    db.close()
    return {"status": "ok"}

@app.post("/admin/genkey")
def genkey():
    db = Session()
    key = generate_key()
    db.add(License(key=key))
    db.commit()
    db.close()
    return {"key": key}

@app.post("/admin/revoke")
def revoke(data: dict):
    key = data.get("key")

    db = Session()
    lic = db.query(License).filter_by(key=key).first()
    if not lic:
        db.close()
        return JSONResponse({"error": "not found"}, status_code=404)

    db.delete(lic)
    db.commit()
    db.close()
    return {"status": "deleted"}

@app.get("/admin/list")
def list_keys():
    db = Session()
    data = [{"key": l.key, "hwid": l.hwid} for l in db.query(License).all()]
    db.close()
    return data
