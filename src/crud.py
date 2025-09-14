from sqlalchemy.orm import Session
from src import models
from src.utils.password_utils import hash_password

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, *, email: str, password: str | None, full_name: str | None, role: str, provider="local"):
    user = models.User(
        email=email,
        hashed_password=hash_password(password) if password else None,
        full_name=full_name,
        role=role,
        provider=provider,
        is_verified=False if provider == "local" else True,  # Google users considered verified
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
