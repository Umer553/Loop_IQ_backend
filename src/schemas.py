from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: str = "agent"  # 'admin' or 'agent'

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str]
    role: str

    class Config:
        orm_mode = True

class ForgotPasswordIn(BaseModel):
    email: EmailStr

class ResetPasswordIn(BaseModel):
    token: str
    new_password: str


class GoogleAuthRequest(BaseModel):
    credential: str

class User(BaseModel):
    id: int
    name: str
    email: str

class Profile(BaseModel):
    id: int
    name: str
    email: str

Profile.update_forward_refs()
User.update_forward_refs()