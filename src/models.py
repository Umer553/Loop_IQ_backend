from sqlalchemy import Column, Integer, String, Boolean
from src.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=True)      
    full_name = Column(String, nullable=True)
    role = Column(String, default="agent")                  # 'admin' | 'agent'
    is_verified = Column(Boolean, default=False)
    provider = Column(String, default="local")              
    verification_token = Column(String, nullable=True)
    reset_token = Column(String, nullable=True)
