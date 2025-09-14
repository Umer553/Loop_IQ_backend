from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.schemas import UserCreate, UserLogin, UserOut, Token
from src.crud import get_user_by_email, create_user
from src.utils.utils import verify_password, create_access_token, decode_access_token, get_password_hash, verify_token
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

@router.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db, user)

@router.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(db_user.email, db_user.role)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/token", response_model=Token)
def token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(user.email, user.role)
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me")
def get_me(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"email": user["email"], "role": user["role"]}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    email, role = decode_access_token(token)
    if not email or role not in ["agent", "admin"]:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_current_active_user(current_user = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_admin_user(current_user = Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

def get_agent_user(current_user = Depends(get_current_active_user)):
    if current_user.role != "agent":
        raise HTTPException(status_code=403, detail="Agent privileges required")
    return current_user

@router.post("/forgot-password")
def forgot_password(email: str, db: Session = Depends(get_db)):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    reset_token = create_access_token(user.email, user.role, expires_delta=timedelta(minutes=15))
    reset_link = f"https://your-frontend/reset-password?token={reset_token}"
    return {"msg": "Password reset link (mock)", "reset_link": reset_link}

@router.post("/reset-password")
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    email, role = decode_access_token(token)
    if not email or role not in ["agent", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    return {"msg": "Password reset successful"}

@router.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie("user_token")
    return {"message": "Logged out successfully"}
