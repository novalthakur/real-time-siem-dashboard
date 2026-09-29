"""
JWT Authentication with open registration.
Users stored in SQLite with hashed passwords.
"""
import os, hashlib
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
from database import get_db

router = APIRouter()
bearer = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "siem-secret-key-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/auth/register")
def register(body: RegisterRequest):
    if len(body.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username=?", (body.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already taken")
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (body.username, hash_password(body.password))
    )
    conn.commit()
    conn.close()
    token = create_token(body.username)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/auth/login")
def login(body: LoginRequest):
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username=?", (body.username,)
    ).fetchone()
    conn.close()
    if not row or row["password_hash"] != hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(body.username)
    return {"access_token": token, "token_type": "bearer"}
