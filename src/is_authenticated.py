from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from jose import jwt, JWTError
from src.utils.auth_utils import SECRET_KEY, ALGORITHM

class IsAuthenticatedMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get("user_token")
        if not token:
            raise HTTPException(status_code=401, detail="Not authenticated")

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user = {"email": payload["sub"], "role": payload["role"]}
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")

        response = await call_next(request)
        return response
