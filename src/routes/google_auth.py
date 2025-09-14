from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests
import os
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from src.database import get_db
from src import crud, models

load_dotenv()

router = APIRouter()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


class GoogleAuthRequest(BaseModel):
    credential: str  

@router.post("/auth/google/")
def google_login(data: GoogleAuthRequest, db: Session = Depends(get_db)):
    try:
        idinfo = id_token.verify_oauth2_token(
            data.credential,
            requests.Request(),
            GOOGLE_CLIENT_ID
        )

        email = idinfo.get("email")
        name = idinfo.get("name")

        if not email:
            raise HTTPException(status_code=400, detail="Google token missing email")

        user = crud.get_user_by_email(db, email=email)
        if not user:
            user = models.User(
                email=email,
                full_name=name,
                role="agent",
                is_verified=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        return {
            "message": "Logged in with Google",
            "email": user.email,
            "role": user.role
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid Google token")
