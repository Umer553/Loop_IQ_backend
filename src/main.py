import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.database import Base, engine
from src.routes import auth, google_auth, admin, agent
from src.middleware.auth_middleware import IsAuthenticatedMiddleware

app = FastAPI(title="Loop IQ Authentication API")

Base.metadata.create_all(bind=engine)

origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if not origins:
    origins = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "https://loop-iq-prod.vercel.app/"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,   
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(IsAuthenticatedMiddleware)

@app.get("/health")
def health():
    return {"status": "ok"}

# Routers
app.include_router(auth.router)
app.include_router(google_auth.router)
app.include_router(admin.router)
app.include_router(agent.router)
