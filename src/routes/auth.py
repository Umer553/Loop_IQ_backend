import os, secrets
from fastapi import APIRouter, Depends, Response, Request, HTTPException
from sqlalchemy.orm import Session
from src import models, schemas, crud, database
from src.utils.password_utils import verify_password, hash_password
from src.utils.auth_utils import create_access_token, decode_token
from src.utils.email import send_email
from fastapi import APIRouter, HTTPException, Response, Depends
from sqlalchemy.orm import Session
from google.oauth2 import id_token
from google.auth.transport import requests
from src.database import get_db
from src.models import User
from src.schemas import GoogleAuthRequest
from src.utils.auth_utils import create_access_token

FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")
COOKIE_NAME = "user_token"

router = APIRouter(prefix="/auth", tags=["Auth"])

@router.post("/signup")
def signup(payload: schemas.UserCreate, response: Response, db: Session = Depends(database.get_db)):
    if crud.get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    # create user (local, unverified)
    user = crud.create_user(
        db, email=payload.email, password=payload.password,
        full_name=payload.full_name, role=payload.role, provider="local"
    )

    # email verification token
    token = secrets.token_urlsafe(32)
    user.verification_token = token
    db.commit()

    verify_url = f"{FRONTEND_ORIGIN}/verify-email?token={token}"
    send_email(
        to=user.email,
        subject="Verify your email",
        body=f"<p>Hi {user.full_name or ''},</p><p>Verify your account: <a href='{verify_url}'>Verify</a></p>"
    )
    return {"message": "User registered. Please verify your email from the link we sent."}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.verification_token == token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    user.is_verified = True
    user.verification_token = None
    db.commit()
    return {"message": "Email verified. You can now log in."}

@router.post("/login")
def login(payload: schemas.UserLogin, response: Response, db: Session = Depends(database.get_db)):
    user = crud.get_user_by_email(db, payload.email)
    if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email first")

    token = create_access_token({"sub": user.email, "role": user.role})
    response.set_cookie(
        key=COOKIE_NAME, value=token, httponly=True, samesite="Lax",
        secure=False, max_age=int(os.getenv("JWT_EXPIRATION", "3600")), path="/"
    )
    return {"message": "Logged in", "role": user.role}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"message": "Logged out"}

@router.get("/me", response_model=schemas.UserOut)
def me(request: Request, db: Session = Depends(database.get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = crud.get_user_by_email(db, payload["sub"])
    return user

@router.post("/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordIn, db: Session = Depends(database.get_db)):
    user = crud.get_user_by_email(db, payload.email)
    if not user:
        # don’t leak user existence
        return {"message": "If the email exists, a reset link has been sent."}
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    db.commit()

    reset_url = f"{FRONTEND_ORIGIN}/reset-password?token={token}"
    send_email(
        to=user.email,
        subject="Reset your password",
        body=f"<p>Hi {user.full_name or ''},</p><p>Reset your password: <a href='{reset_url}'>Reset</a></p>"
    )
    return {"message": "If the email exists, a reset link has been sent."}

@router.post("/reset-password")
def reset_password(payload: schemas.ResetPasswordIn, db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.reset_token == payload.token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    user.hashed_password = hash_password(payload.new_password)
    user.reset_token = None
    db.commit()
    return {"message": "Password reset successful"}



@router.post("/auth/google")
def google_login(data: GoogleAuthRequest, response: Response, db: Session = Depends(get_db)):
    try:
        idinfo = id_token.verify_oauth2_token(data.credential, requests.Request(), "YOUR_GOOGLE_CLIENT_ID")

        email = idinfo.get("email")
        name = idinfo.get("name")

        if not email:
            raise HTTPException(status_code=400, detail="Google token invalid")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            user = User(email=email, full_name=name, is_verified=True, role="agent")
            db.add(user)
            db.commit()
            db.refresh(user)
        token = create_access_token({"sub": user.email, "role": user.role})
        response.set_cookie(key="user_token", value=token, httponly=True, samesite="Lax")

        return {"message": "Logged in with Google", "role": user.role}

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Google token")