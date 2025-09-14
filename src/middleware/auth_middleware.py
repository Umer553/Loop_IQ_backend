from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from src.utils.auth_utils import decode_token
from src import crud, database

PUBLIC_PREFIXES = [
    "/auth/login", "/auth/signup", "/auth/logout",
    "/auth/verify-email", "/auth/forgot-password", "/auth/reset-password",
    "/auth/google",
    "/docs", "/openapi.json", "/redoc", "/health"
]

class IsAuthenticatedMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in PUBLIC_PREFIXES):
            return await call_next(request)

        token = request.cookies.get("user_token")
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")

        payload = decode_token(token)
        if not payload or "sub" not in payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        db = database.SessionLocal()
        try:
            user = crud.get_user_by_email(db, payload["sub"])
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            request.state.user = user
        finally:
            db.close()

        return await call_next(request)
